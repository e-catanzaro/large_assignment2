use crate::SystemRegisterCommandContent::Value;
use crate::{Broadcast, ClientRegisterCommand, ClientRegisterCommandContent, OperationReturn, OperationSuccess, ReadReturn, RegisterClient, SectorIdx, SectorVec, SectorsManager, SystemCommandHeader, SystemRegisterCommand, SystemRegisterCommandContent};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait AtomicRegister: Send + Sync {
    /// Handle a client command. After the command is completed, we expect
    /// callback to be called. Note that completion of client command happens after
    /// delivery of multiple system commands to the register, as the algorithm specifies.
    ///
    /// This function corresponds to the handlers of Read and Write events in the
    /// (N,N)-AtomicRegister algorithm.
    async fn client_command(
        &mut self,
        cmd: ClientRegisterCommand,
        success_callback: Box<
            dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output = ()> + Send>>
            + Send
            + Sync,
        >,
    );

    /// Handle a system command.
    ///
    /// This function corresponds to the handlers of READ_PROC, VALUE, WRITE_PROC
    /// and ACK messages in the (N,N)-AtomicRegister algorithm.
    async fn system_command(&mut self, cmd: SystemRegisterCommand);
}

/// Idents are numbered starting at 1 (up to the number of processes in the system).
/// Communication with other processes of the system is to be done by register_client.
/// And sectors must be stored in the sectors_manager instance.
///
/// This function corresponds to the handlers of Init and Recovery events in the
/// (N,N)-AtomicRegister algorithm.
pub async fn build_atomic_register(
    self_ident: u8,
    sector_idx: SectorIdx,
    register_client: Arc<dyn RegisterClient>,
    sectors_manager: Arc<dyn SectorsManager>,
    processes_count: u8
) -> Box<dyn AtomicRegister> {
    Box::new(NNAtomicRegister::build(
        self_ident, sector_idx, register_client, sectors_manager, processes_count
    ).await)
}

#[derive(Clone)]
struct Triple {
    ts : u64,
    wr : u8,
    val : SectorVec,
}


pub(crate) struct NNAtomicRegister {
    rank : u8,
    sector_idx : SectorIdx,
    n_proc : u8,
    register_client: Arc<dyn RegisterClient>,
    sectors_manager: Arc<dyn SectorsManager>,

    data : Triple,
    op_id : Option<Uuid>,
    read_list : HashMap<u8, Triple>,
    ack_list : HashSet<u8>,
    reading : bool,
    write_val : Option<SectorVec>,
    writing : bool,
    write_phase: bool,
    read_val : Option<SectorVec>,
    callback : Option<Box<dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output=()> + Send>> + Send + Sync>>,
    request_id : Option<u64>
}

impl NNAtomicRegister {
    pub(crate) async fn build(self_ident: u8,
                              sector_idx: SectorIdx,
                              register_client: Arc<dyn RegisterClient>,
                              sectors_manager: Arc<dyn SectorsManager>,
                              processes_count: u8) -> Self{
        let (ts, wr) = sectors_manager.read_metadata(sector_idx).await;
        let val = sectors_manager.read_data(sector_idx).await;
        Self{
            rank: self_ident,
            sector_idx,
            n_proc: processes_count,
            register_client,
            sectors_manager,
            data: Triple { ts, wr, val },
            op_id: None,
            read_list: HashMap::new(),
            ack_list: HashSet::new(),
            reading: false,
            write_val: None,
            writing: false,
            write_phase: false,
            read_val: None,
            callback: None,
            request_id: None,
        }
    }
}

#[async_trait::async_trait]
impl AtomicRegister for NNAtomicRegister {
    async fn client_command(&mut self, cmd: ClientRegisterCommand, success_callback: Box<dyn FnOnce(OperationSuccess) -> Pin<Box<dyn Future<Output=()> + Send>> + Send + Sync>) {
        self.op_id = Some(Uuid::new_v4());
        self.ack_list.clear();
        self.read_list.clear();
        self.request_id = Some(cmd.header.request_identifier);
        self.callback = Some(success_callback);

        match cmd.content {
            ClientRegisterCommandContent::Read => {
                self.reading = true;
            }
            ClientRegisterCommandContent::Write { data } => {
                self.write_val = Some(data);
                self.writing = true;
            }
        }

        let read_proc = SystemRegisterCommand{
            header: SystemCommandHeader {
                process_identifier: self.rank,
                msg_ident: self.op_id.unwrap(),
                sector_idx: self.sector_idx,
            },
            content: SystemRegisterCommandContent::ReadProc,
        };

        self.register_client.broadcast(Broadcast {
            cmd: Arc::new(read_proc),
        }).await;
    }

    async fn system_command(&mut self, cmd: SystemRegisterCommand) {
        match cmd.content {
            SystemRegisterCommandContent::ReadProc => {
                let value = SystemRegisterCommand{
                    header: SystemCommandHeader {
                        process_identifier: self.rank,
                        msg_ident: cmd.header.msg_ident,
                        sector_idx: self.sector_idx,
                    },
                    content: Value{
                        timestamp: self.data.ts,
                        write_rank: self.data.wr,
                        sector_data: self.data.val.clone(),
                    },
                };
                self.register_client.send(crate::Send{
                    cmd: Arc::new(value),
                    target: cmd.header.process_identifier,
                }).await;
            }
            SystemRegisterCommandContent::Value { timestamp, write_rank, sector_data } => {
                if self.op_id.is_none() {return;}
                if self.op_id.unwrap() != cmd.header.msg_ident || self.write_phase { return; }

                self.read_list.insert(cmd.header.process_identifier, Triple{
                    ts: timestamp,
                    wr: write_rank,
                    val: sector_data,
                });

                if self.read_list.len() > self.n_proc as usize / 2 && (self.reading || self.writing) {
                    self.read_list.insert(self.rank, self.data.clone());

                    let mut values = self.read_list.values().collect::<Vec<&Triple>>();
                    values.sort_by(|t1, t2| t1.ts.cmp(&t2.ts).then(t1.wr.cmp(&t2.wr)));
                    let highest = values[values.len() - 1].clone();
                    self.read_val = Some(highest.val.clone());

                    self.read_list.clear();
                    self.ack_list.clear();
                    self.write_phase = true;

                    if self.reading {
                        let write_proc = SystemRegisterCommand {
                            header: SystemCommandHeader {
                                process_identifier: self.rank,
                                msg_ident: cmd.header.msg_ident,
                                sector_idx: self.sector_idx,
                            },
                            content: SystemRegisterCommandContent::WriteProc {
                                timestamp: highest.ts,
                                write_rank: highest.wr,
                                data_to_write: highest.val,
                            },
                        };
                        self.register_client.broadcast(Broadcast {
                            cmd: Arc::new(write_proc) }).await;
                    } else {
                        self.data = Triple{
                            ts: highest.ts + 1,
                            wr: self.rank,
                            val: self.write_val.clone().unwrap(),
                        } ;
                        self.sectors_manager.write(self.sector_idx, &(self.data.val.clone(), self.data.ts, self.data.wr  )).await;
                        let write_proc = SystemRegisterCommand{
                            header: SystemCommandHeader {
                                process_identifier: self.rank,
                                msg_ident: cmd.header.msg_ident,
                                sector_idx: self.sector_idx,
                            },
                            content: SystemRegisterCommandContent::WriteProc{
                                timestamp : highest.ts + 1,
                                write_rank : self.rank,
                                data_to_write: self.write_val.take().unwrap(),
                            },
                        };
                        self.register_client.broadcast(Broadcast{
                            cmd: Arc::new(write_proc),
                        }).await;
                    }
                }
            }
            SystemRegisterCommandContent::WriteProc { timestamp, write_rank, data_to_write } => {
                let rec_triple = Triple{
                    ts: timestamp,
                    wr: write_rank,
                    val: data_to_write,
                };
                if self.data.ts.cmp(&rec_triple.ts).then(self.data.wr.cmp(&rec_triple.wr)).is_le() {
                    self.data = rec_triple;
                    self.sectors_manager.write(self.sector_idx, &(self.data.val.clone(), self.data.ts, self.data.wr)).await;
                }
                let ack = SystemRegisterCommand{
                    header: SystemCommandHeader {
                        process_identifier: self.rank,
                        msg_ident: cmd.header.msg_ident,
                        sector_idx: self.sector_idx,
                    },
                    content: SystemRegisterCommandContent::Ack,
                };
                self.register_client.send(crate::Send{
                    cmd: Arc::new(ack),
                    target: cmd.header.process_identifier,
                }).await;
            }
            SystemRegisterCommandContent::Ack => {
                if self.op_id.is_none() {return;}
                if self.op_id.unwrap() != cmd.header.msg_ident || ! self.write_phase { return; }
                self.ack_list.insert(cmd.header.process_identifier);
                if self.ack_list.len() > self.n_proc as usize / 2 && (self.reading || self.writing) {
                    self.ack_list.clear();
                    self.write_phase = false;

                    if self.reading {
                        self.reading = false;
                        let read_return = OperationSuccess{
                            request_identifier: self.request_id.take().unwrap(),
                            op_return: OperationReturn::Read(ReadReturn { read_data: self.read_val.take().unwrap() }),
                        };
                        self.callback.take().unwrap()(read_return).await;
                    } else {
                        self.writing = false;
                        let write_return = OperationSuccess{
                            request_identifier: self.request_id.take().unwrap(),
                            op_return: OperationReturn::Write,
                        };
                        self.callback.take().unwrap()(write_return).await;
                    }
                }
            }
        }
    }
}

