use crate::transfer::OperationError::{InvalidMac, InvalidSector};
use crate::{is_hmac_tag_valid, HmacSha256, OperationReturn, OperationSuccess, ReadReturn, SectorVec, StatusCode, SystemRegisterCommand, SystemRegisterCommandContent, MAGIC_NUMBER, SECTOR_SIZE};
use hmac::Mac;
use std::collections::VecDeque;
use std::io::ErrorKind::InvalidInput;
use std::io::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub enum RegisterResponse {
    ReadResponse(OperationResult),
    WriteResponse(OperationResult)
}

#[derive(Debug, Clone)]
pub enum OperationResult {
    Return(OperationSuccess),
    Error(OperationError)
}

#[derive(Debug, Clone)]
pub enum OperationError {
    InvalidMac(u64),
    InvalidSector(u64)
}

pub async fn serialize_response(response: &RegisterResponse,
                                writer: &mut (dyn AsyncWrite + Send + Unpin),
                                hmac_key: &[u8]) -> Result<(), Error> {
    let mut raw_message : Vec<u8> = [MAGIC_NUMBER.to_vec(), [0u8;2].to_vec()].concat();
    let (operation_result,msg_type)  = match response {
        RegisterResponse::ReadResponse(r) => (r, 0x41u8),
        RegisterResponse::WriteResponse(r) => (r,0x42u8)
    };

    let (status_code, request_number) = match operation_result {
        OperationResult::Return(succ) => (StatusCode::Ok,succ.request_identifier) ,
        OperationResult::Error(e) => {
            match e {
                OperationError::InvalidMac(req_number) => (StatusCode::AuthFailure,*req_number) ,
                OperationError::InvalidSector(req_number) => (StatusCode::InvalidSectorIndex,*req_number) ,
            }
        }
    };

    raw_message = [raw_message, vec![status_code as u8], vec![msg_type], request_number.to_be_bytes().to_vec()].concat();

    // only a successful ReadResponse has a content
    if let RegisterResponse::ReadResponse(response) = response {
        if let OperationResult::Return(succes) = response {
            if let OperationReturn::Read(read_value) = succes.clone().op_return{
                raw_message = [raw_message, read_value.read_data.0].concat();
            }
        }
    }

    let mut sha = HmacSha256::new_from_slice(hmac_key).unwrap();
    sha.update(raw_message.as_slice());
    raw_message = [raw_message, sha.finalize().into_bytes().to_vec()].concat();

    writer.write_all(&raw_message).await?;
    Ok(())
}

pub async fn deserialize_response(data: &mut (dyn AsyncRead + Send + Unpin),
                                  hmac_key: &[u8; 64],) -> Result<(RegisterResponse, bool), Error>{
    let mut window : VecDeque<u8> = VecDeque::from(vec![0;4]);
    data.read_exact(&mut window.make_contiguous()).await?;

    while window.make_contiguous() != MAGIC_NUMBER {
        window.pop_front();
        window.push_back(data.read_u8().await?);
    }

    let mut padding = [0u8; 4];
    data.read_exact(&mut padding).await?;
    let mut raw_message= [MAGIC_NUMBER.to_vec(), padding.to_vec()].concat();
    let message_type : u8 = padding[3];
    let ret_type : u8 = padding[2];

    match message_type{
        0x41 => {
            let mut message_content = [0u8;16 + SECTOR_SIZE];
            data.read_exact(&mut message_content).await?;
            raw_message = [ raw_message, message_content.to_vec()].concat();
        },
        0x42 => {
            let mut message_content = [0u8;16];
            data.read_exact(&mut message_content).await?;
            raw_message = [ raw_message, message_content.to_vec()].concat();
        },
        _ => return Err(Error::new(InvalidInput, "invalid message type"))
    }


    let mut hash : [u8;32] = [0u8;32];
    data.read_exact(&mut hash).await?;
    raw_message = [raw_message, hash.to_vec()].concat();

    let ret = match ret_type {
        0x0 =>{
            let mut req_id = [0u8;8];
            req_id.copy_from_slice(&raw_message[8..16]);

            OperationResult::Return(OperationSuccess{
                request_identifier: u64::from_be_bytes(req_id),
                op_return: match message_type {
                    0x41 => OperationReturn::Read(ReadReturn{ read_data: SectorVec{0: raw_message[16..16+SECTOR_SIZE].to_vec()} } ),
                    0x42 => OperationReturn::Write,
                    _ => unreachable!(),
                },
            })
        }
        0x1 => OperationResult::Error(InvalidMac(0)),
        0x2 => OperationResult::Error(InvalidSector(0)),
        _ => return Err(Error::new(InvalidInput, "invalid message type"))
    };

    let reg_response = match message_type {
        0x41 => RegisterResponse::ReadResponse(ret),
        0x42 => RegisterResponse::WriteResponse(ret),
        _ => unreachable!()
    };

    Ok((reg_response,  is_hmac_tag_valid(raw_message.as_slice(), hmac_key)))
}

#[derive(Clone,Hash,Eq,PartialEq,Copy)]
pub enum AckType {
    ReadProc,
    Value,
    WriteProc,
    ACK,
}

#[derive(Clone,Hash,Eq,PartialEq,Copy)]
pub struct Acknowledgment {
    pub proc_id: u8,
    pub msg_type : AckType,
    pub op_id: Uuid,
}

impl Acknowledgment {
    pub fn from_cmd(cmd: SystemRegisterCommand, target_rank : u8) -> Self {
        Self {
            msg_type:  match cmd.content {
                SystemRegisterCommandContent::ReadProc => AckType::ReadProc,
                SystemRegisterCommandContent::Value { .. } => AckType::Value,
                SystemRegisterCommandContent::WriteProc { .. } => AckType::WriteProc,
                SystemRegisterCommandContent::Ack => AckType::ACK,
            },
            proc_id: target_rank,
            op_id: cmd.header.msg_ident
        }
    }
}

pub async fn deserialize_ack(data: &mut (dyn AsyncRead + Send + Unpin),
                             hmac_key: &[u8; 64],) -> Result<(Acknowledgment, bool), Error>{
    let mut window : VecDeque<u8> = VecDeque::from(vec![0;4]);
    data.read_exact(&mut window.make_contiguous()).await?;

    while window.make_contiguous() != MAGIC_NUMBER {
        window.pop_front();
        window.push_back(data.read_u8().await?);
    }

    let mut padding = [0u8; 4];
    data.read_exact(&mut padding).await?;
    let mut raw_message= [MAGIC_NUMBER.to_vec(), padding.to_vec()].concat();
    let raw_msg_type: u8 = padding[3];
    let rank : u8 = padding[2];

    let msg_type = match raw_msg_type {
        0x43 => AckType::ReadProc,
        0x44 => AckType::Value,
        0x45 => AckType::WriteProc,
        0x46 => AckType::ACK,
        _ => return Err(Error::new(InvalidInput, "invalid message type"))
    };

    let mut remaining_message = [0u8; 16+32];
    data.read_exact(&mut remaining_message).await?;
    raw_message = [raw_message, remaining_message.to_vec()].concat();

    let mut proc_id_bytes = [0u8;16];
    proc_id_bytes.copy_from_slice(&remaining_message[..16]);

    let ack = Acknowledgment {
        proc_id: rank,
        msg_type,
        op_id: Uuid::from_bytes(uuid::Bytes::from(proc_id_bytes)),
    };

    Ok((ack,  is_hmac_tag_valid(raw_message.as_slice(), hmac_key)))
}

pub async fn serialize_ack(response: &Acknowledgment,
                           writer: &mut (dyn AsyncWrite + Send + Unpin),
                           hmac_key: &[u8]) -> Result<(), Error> {

    let mut raw_message : Vec<u8> = [MAGIC_NUMBER.to_vec(), [0u8;2].to_vec()].concat();
    raw_message = [raw_message, response.proc_id.to_be_bytes().to_vec()].concat();

    let type_bytes = match response.msg_type {
        AckType::ReadProc => 0x43u8,
        AckType::Value => 0x44u8,
        AckType::WriteProc => 0x45u8,
        AckType::ACK => 0x46u8,
    }.to_be_bytes().to_vec();

    raw_message = [raw_message, type_bytes, response.op_id.as_bytes().to_vec()].concat();

    let mut sha = HmacSha256::new_from_slice(hmac_key).unwrap();
    sha.update(raw_message.as_slice());
    raw_message = [raw_message, sha.finalize().into_bytes().to_vec()].concat();

    writer.write_all(&raw_message).await?;
    Ok(())
}

