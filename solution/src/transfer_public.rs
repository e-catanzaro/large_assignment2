use crate::{ClientCommandHeader, ClientRegisterCommand, ClientRegisterCommandContent, RegisterCommand, SectorVec, SystemCommandHeader, SystemRegisterCommand, SystemRegisterCommandContent, MAGIC_NUMBER};

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::VecDeque;
use std::io::ErrorKind::InvalidInput;
use std::io::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const SECTOR_SIZE: usize = 4096;

type HmacSha256 = Hmac<Sha256>;

pub fn is_hmac_tag_valid(message : &[u8], hash_key: &[u8]) -> bool {
    let mut sha = HmacSha256::new_from_slice(hash_key).unwrap();
    sha.update(&message[..message.len()-32]);
    sha.verify_slice(&message[(message.len() - 32)..]).is_ok()
}

pub async fn deserialize_register_command(
    data: &mut (dyn AsyncRead + Send + Unpin),
    hmac_system_key: &[u8; 64],
    hmac_client_key: &[u8; 32],
) -> Result<(RegisterCommand, bool), Error> {

    let mut window : VecDeque<u8> = VecDeque::from(vec![0;4]);
    data.read_exact(&mut window.make_contiguous()).await?;

    while window.make_contiguous() != MAGIC_NUMBER {
        window.pop_front();
        window.push_back(data.read_u8().await?);
    }

    let mut padding= [0u8; 3];
    data.read_exact(&mut padding).await?;
    let message_type : u8 = data.read_u8().await?;

    match message_type {
        0x01 | 0x02 => {
            let raw_message;
            if message_type == 0x01 {
                let mut buffer = [0u8; 48];
                data.read_exact(&mut buffer).await?;
                raw_message = buffer.to_vec();
            } else {
                let mut buffer = [0u8; 48 + SECTOR_SIZE];
                data.read_exact(&mut buffer).await?;
                raw_message = buffer.to_vec();
            }

            let mut r = [0u8;8];
            r.copy_from_slice(&raw_message[..8]);
            let mut s= [0u8;8];
            s.copy_from_slice(&raw_message[8..16]);

            let header : ClientCommandHeader = ClientCommandHeader {
                request_identifier: u64::from_be_bytes( r),
                sector_idx: u64::from_be_bytes(s),
            };
            let content  = match message_type {
                0x01 => ClientRegisterCommandContent::Read,
                0x02 => ClientRegisterCommandContent::Write{
                    data: SectorVec{ 0:  raw_message[16..(16+SECTOR_SIZE)].to_vec() },
                },
                _ => unreachable!()
            };

            let is_ok = is_hmac_tag_valid([MAGIC_NUMBER.as_slice(), padding.as_slice(), &message_type.to_be_bytes(), raw_message.as_slice()].concat().as_slice(), hmac_client_key);
            Ok((RegisterCommand::Client(ClientRegisterCommand{ header, content,}),is_ok))
        },
        0x03 | 0x04 | 0x05 | 0x06 =>{
            let raw_message;
            match message_type {
                0x03 | 0x06 => {
                    let mut buffer = [0u8; 56];
                    data.read_exact(&mut buffer).await?;
                    raw_message = buffer.to_vec();
                },
                0x04 | 0x05=> {
                    let mut buffer = [0u8; 72+SECTOR_SIZE];
                    data.read_exact(&mut buffer).await?;
                    raw_message = buffer.to_vec();
                },
                _ =>  unreachable!()
            }

            let mut m = [0u8;16];
            m.copy_from_slice(&raw_message[..16]);
            let mut s = [0u8;8];
            s.copy_from_slice(&raw_message[16..24]);
            let header = SystemCommandHeader{
                process_identifier: padding[2],
                msg_ident: Uuid::from_bytes(uuid::Bytes::from(m) ) ,
                sector_idx: u64::from_be_bytes(s),
            };
            let content  = match message_type {
                0x03 => SystemRegisterCommandContent::ReadProc,
                0x04 => {
                    let mut t = [0u8;8];
                    t.copy_from_slice(&raw_message[24..32]);
                    SystemRegisterCommandContent::Value {
                        timestamp: u64::from_be_bytes(t),
                        write_rank: raw_message[39],
                        sector_data: SectorVec{ 0 : raw_message[40..40+SECTOR_SIZE].to_vec() },
                    }
                },
                0x05 => {
                    let mut t = [0u8;8];
                    t.copy_from_slice(&raw_message[24..32]);
                    SystemRegisterCommandContent::WriteProc {
                        timestamp: u64::from_be_bytes(t),
                        write_rank: raw_message[39],
                        data_to_write: SectorVec{ 0 : raw_message[40..40+SECTOR_SIZE].to_vec() },
                    }
                },
                0x06 => SystemRegisterCommandContent::Ack,
                _ => unreachable!()
            };

            let is_ok = is_hmac_tag_valid([MAGIC_NUMBER.as_slice(), padding.as_slice(), &message_type.to_be_bytes(), raw_message.as_slice()].concat().as_slice(), hmac_system_key);
            Ok((RegisterCommand::System(SystemRegisterCommand{ header, content,}),is_ok))
        },
        _ =>  Err(Error::new(InvalidInput, "Invalid message type"))
    }
}

pub async fn serialize_register_command(
    cmd: &RegisterCommand,
    writer: &mut (dyn AsyncWrite + Send + Unpin),
    hmac_key: &[u8],
) -> Result<(), Error> {

    let mut raw_message : Vec<u8> = [MAGIC_NUMBER.to_vec(), [0u8;2].as_slice().to_vec()].concat();
    match cmd {
        RegisterCommand::Client(cmd)=>{
            raw_message = [raw_message, [0u8;1].as_slice().to_vec()].concat();
            match cmd.content {
                ClientRegisterCommandContent::Read => {raw_message = [raw_message, vec![0x01u8]].concat()}
                ClientRegisterCommandContent::Write { .. } => { raw_message = [raw_message, vec![0x02u8]].concat() }
            }
            raw_message = [raw_message, cmd.header.request_identifier.to_be_bytes().to_vec(), cmd.header.sector_idx.to_be_bytes().to_vec()].concat();
            if let ClientRegisterCommandContent::Write{data } = cmd.content.clone() {
                raw_message = [raw_message, data.0].concat();
            }

        },
        RegisterCommand::System(cmd)=>{
            raw_message = [raw_message, vec![cmd.header.process_identifier]].concat();
            match cmd.content {
                SystemRegisterCommandContent::ReadProc => raw_message = [raw_message, vec![0x03u8]].concat(),
                SystemRegisterCommandContent::Value {..} => raw_message = [raw_message, vec![0x04u8]].concat(),
                SystemRegisterCommandContent::WriteProc {..} => raw_message = [raw_message, vec![0x05u8]].concat(),
                SystemRegisterCommandContent::Ack => raw_message = [raw_message, vec![0x06u8]].concat(),
            }
            raw_message = [raw_message, cmd.header.msg_ident.as_bytes().to_vec() ,cmd.header.sector_idx.to_be_bytes().to_vec()].concat();
            match cmd.content.clone() {
                SystemRegisterCommandContent::ReadProc => {},
                SystemRegisterCommandContent::Value { timestamp, write_rank, sector_data } =>
                    raw_message = [raw_message, timestamp.to_be_bytes().to_vec(), vec![0u8;7], write_rank.to_be_bytes().to_vec(), sector_data.0.to_vec()].concat(),
                SystemRegisterCommandContent::WriteProc { timestamp, write_rank, data_to_write } =>
                    raw_message = [raw_message, timestamp.to_be_bytes().to_vec(), vec![0u8;7], write_rank.to_be_bytes().to_vec(), data_to_write.0.to_vec()].concat(),
                SystemRegisterCommandContent::Ack => {},
            }
        }
    }

    let mut sha = HmacSha256::new_from_slice(hmac_key).unwrap();
    sha.update(raw_message.as_slice());
    let sha_tag = sha.finalize().into_bytes();

    raw_message = [raw_message, sha_tag.as_slice().to_vec()].concat();
    writer.write_all(&raw_message).await?;
    Ok(())
}