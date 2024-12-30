use crate::stubborn_register_client::timer::TickHandler;
use crate::transfer::{deserialize_ack, Acknowledgment};
use crate::{serialize_register_command, RegisterCommand, SystemRegisterCommand};
use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct StubbornLink{
    rank : u8, // rank of the process associated with the stubborn link
    acks_queue : Arc<Mutex<HashMap<Acknowledgment, TickHandler>>>,
    channel : UnboundedSender<Arc<SystemRegisterCommand>>,
}

impl StubbornLink{
    pub fn new( rank : u8, locations: Vec<(String, u16)>, system_hmac_key : Arc<[u8;64]>) -> StubbornLink{
        let (msg_tx, mut msg_rx) = unbounded_channel();
        let (stream_tx, mut stream_rx) = unbounded_channel();
        let (addr, port) : (String, u16) = locations[rank as usize -1].clone();
        let sl = StubbornLink{
            rank,
            acks_queue: Arc::new(Mutex::new(HashMap::new())),
            channel : msg_tx,
        };

        let sl_clone = sl.clone();
        let key_clone = system_hmac_key.clone();

        tokio::spawn(async move {
            loop{
                let Ok(stream) = TcpStream::connect((addr.clone() ,port)).await else {continue;};
                let (mut stream_read, stream_write) = stream.into_split();
                let _ = stream_tx.send(stream_write);

                loop {

                    let mut one_byte = [0u8;1];
                    let res = stream_read.peek(&mut one_byte).await;

                    if res.is_err() {
                        break;
                    } else if let Ok(0) = res {
                        break;
                    }

                    if let Ok((msg, true)) =  deserialize_ack(&mut stream_read, key_clone.deref()).await {
                        sl_clone.ack_received(msg).await;
                    }
                }

            }

        }) ;

        tokio::spawn(async move {

            let Some(mut stream_w) = stream_rx.recv().await else {
                return;
            };

            loop {
                tokio::select! {
                   biased;
                   Some(new_stream) = stream_rx.recv() => { stream_w= new_stream; } ,
                   Some(msg) = msg_rx.recv() => { _ = serialize_register_command(&RegisterCommand::System(msg.deref().clone()) , &mut stream_w, system_hmac_key.clone().deref()).await; },
                   else => {break;},
               }
            }
        });

        sl
    }

    async fn ack_received(&self, ack : Acknowledgment) {
        if let Some(handler) = self.acks_queue.lock().await.remove(&ack){
            handler.stop().await;
        }
    }

    // adds an ack to queue of messages after a message is received
    pub async fn send_message(&self, message : Arc<SystemRegisterCommand>){

        // prototype of the answer I should get
        let ack = Acknowledgment::from_cmd(message.deref().clone());

        let tick_handle = TickHandler::start_ticks(message, Duration::from_millis(300), self.channel.clone());

        self.acks_queue.lock().await.insert(ack, tick_handle);
    }
}