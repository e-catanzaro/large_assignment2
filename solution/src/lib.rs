use crate::registers_manager::RegManager;
use crate::stubborn_register_client::StubbornRegisterClient;
use crate::transfer::{serialize_ack, serialize_response, Acknowledgment, OperationError, OperationResult, RegisterResponse};
pub use atomic_register_public::*;
pub use domain::*;
use hmac::Hmac;
pub use register_client_public::*;
pub use sectors_manager_public::*;
use sha2::Sha256;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::Arc;
use tokio::io::AsyncRead;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
pub use transfer_public::*;

mod domain;
mod transfer_public;
mod atomic_register_public;
mod sectors_manager_public;
mod register_client_public;

mod stubborn_register_client;
mod transfer;
mod registers_manager;

type HmacSha256 = Hmac<Sha256>;
type SuccessCallbackType = Box<dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output=()> + std::marker::Send>> + std::marker::Send + Sync>;
type SystemCallbackType = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output=()> + std::marker::Send>> + std::marker::Send + Sync>;

pub async fn run_register_process(config: Configuration) {
    let (system_tx, system_rx) = unbounded_channel();
    let (client_tx, client_rx) = unbounded_channel();

    let system_key = Arc::new(config.hmac_system_key);
    let client_key = Arc::new(config.hmac_client_key);

    let sectors_manager = build_sectors_manager(config.public.storage_dir).await;
    let stub_reg_client = Arc::new(StubbornRegisterClient::build(config.public.tcp_locations.clone(), system_key.clone(), config.public.self_rank, system_tx.clone()));

    let data_socket = config.public.tcp_locations.get((config.public.self_rank - 1) as usize).unwrap();
    let listener = TcpListener::bind((data_socket.0.as_str(), data_socket.1)).await.unwrap();

    let registers_manager = RegManager::build(
        config.public.self_rank,
        stub_reg_client,
        sectors_manager,
        config.public.tcp_locations.len() as u8
    );

    tokio::spawn(listen_commands(system_rx, client_rx, registers_manager));

    loop {
        let (stream, _) = listener.accept().await.unwrap();

        tokio::spawn(handle_stream(
            stream,
            system_key.clone(),
            client_key.clone(),
            config.public.n_sectors,
            config.public.self_rank,
            system_tx.clone(),
            client_tx.clone()
        ));
    }
}

async fn listen_commands(mut sys_queue: UnboundedReceiver<(SystemRegisterCommand, SystemCallbackType)>,
                         mut queue_client: UnboundedReceiver<(ClientRegisterCommand, SuccessCallbackType)>,
                         registers_manager: RegManager) {
    loop {
        tokio::select! {
            Some((cmd, cb)) = sys_queue.recv() => {
                registers_manager.system_to_handle(cmd, cb);
            },
            Some((cmd, cb)) = queue_client.recv() => {
                registers_manager.client_to_handle(cmd, cb);
            }
        }
    }
}

async fn handle_stream(stream: TcpStream,
                       system_key: Arc<[u8; 64]>,
                       client_key: Arc<[u8; 32]>,
                       n_sectors: u64,
                       rank: u8,
                       system_tx: UnboundedSender<(SystemRegisterCommand, SystemCallbackType)>,
                       client_tx: UnboundedSender<(ClientRegisterCommand, SuccessCallbackType)>) {
    let (mut read_stream, write_stream) = stream.into_split();
    let (client_success_tx, client_success_rx) = unbounded_channel();
    let (system_success_tx, system_success_rx) = unbounded_channel();

    tokio::spawn(handle_write(
        client_success_rx, system_success_rx, write_stream, client_key.clone(), system_key.clone()
    ));

    loop {
        let mut buf = [0u8; 1];
        if let Ok(0) = read_stream.peek(&mut buf).await {
            return;
        }

        let (command, is_valid) = extract_next_command(&mut read_stream, &system_key, &client_key).await;
        let idx = get_index_cmd(&command);

        if !is_command_ok(&command, is_valid, idx, n_sectors, client_success_tx.clone()).await {
            continue;
        }

        match command {
            RegisterCommand::Client(command) => {
                let client_success_tx = client_success_tx.clone();

                let callback: SuccessCallbackType = Box::new(|success| Box::pin(
                    async move {
                        let response = match &success.op_return {
                            OperationReturn::Read(_) => RegisterResponse::ReadResponse(OperationResult::Return(success)),
                            OperationReturn::Write => RegisterResponse::WriteResponse(OperationResult::Return(success))
                        };

                        client_success_tx.send(response).unwrap()
                    }
                ));

                client_tx.send((command, callback)).unwrap();
            },
            RegisterCommand::System(command) => {
                let system_success_tx = system_success_tx.clone();

                let ack = Arc::new(Acknowledgment::from_cmd(command.clone(), rank));

                let callback: SystemCallbackType = Box::new(|| Box::pin(async move {
                    system_success_tx.send(*ack.deref()).unwrap()
                }));

                system_tx.send((command, callback)).unwrap();
            }
        }
    }
}

async fn handle_write(mut client_success_rx: UnboundedReceiver<RegisterResponse>,
                      mut system_success_rx: UnboundedReceiver<Acknowledgment>,
                      mut write_stream: OwnedWriteHalf,
                      client_key: Arc<[u8; 32]>,
                      system_key: Arc<[u8; 64]>) {
    loop {
        tokio::select! {
            Some(response) = client_success_rx.recv() => {
                serialize_response(&response, &mut write_stream, client_key.deref()).await.unwrap();
            },
            Some(ack) = system_success_rx.recv() => {
                serialize_ack(&ack, &mut write_stream, system_key.deref()).await.unwrap();
            },
            else => break
        }
    }
}

async fn extract_next_command(tcp_stream: &mut (dyn AsyncRead + std::marker::Send + Unpin),
                              system_key: &[u8; 64],
                              client_key: &[u8; 32]) -> (RegisterCommand, bool) {
    loop {
        let result = deserialize_register_command(tcp_stream, system_key, client_key).await;

        if let Ok(command) = result {
            return command;
        }
    };
}

async fn is_command_ok(command: &RegisterCommand,
                       is_hmac_valid: bool,
                       sector_idx: SectorIdx,
                       n_sectors: u64,
                       client_success_tx: UnboundedSender<RegisterResponse>) -> bool {
    if is_hmac_valid && sector_idx < n_sectors {
        return true;
    }

    if let RegisterCommand::Client(command) = &command  {
        let req_id = command.header.request_identifier;

        let err = if !is_hmac_valid {
            OperationError::InvalidMac(req_id)
        } else {
            OperationError::InvalidSector(req_id)
        };

        let err = OperationResult::Error(err);

        let response = match command.content {
            ClientRegisterCommandContent::Read => RegisterResponse::ReadResponse(err),
            ClientRegisterCommandContent::Write { .. } => RegisterResponse::WriteResponse(err)
        };

        client_success_tx.send(response).unwrap();
    }

    false
}

fn get_index_cmd(command: &RegisterCommand) -> SectorIdx {
    match command {
        RegisterCommand::Client(cmd) => cmd.header.sector_idx,
        RegisterCommand::System(cmd) => cmd.header.sector_idx
    }
}