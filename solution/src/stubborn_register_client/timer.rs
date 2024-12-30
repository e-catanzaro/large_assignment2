use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::{Sender, UnboundedSender};
use tokio::time;
use crate::SystemRegisterCommand;

struct StopTheTicks {}

pub(crate) struct TickHandler {
    stop_tx : Sender<StopTheTicks>
}

impl TickHandler {
    pub(crate) async fn stop(&self) {
        let _ = self.stop_tx.send(StopTheTicks {});
    }

    pub(crate) fn start_ticks(msg : Arc<SystemRegisterCommand>, interval : Duration, sender : UnboundedSender<Arc<SystemRegisterCommand>>) -> TickHandler {

        let (stop_tx, mut stop_rx) = mpsc::channel::<StopTheTicks>(1);

        tokio::spawn(async move {
            let mut interval = time::interval(interval);

            loop{
                tokio::select! {
                    biased;
                    Some(_) = stop_rx.recv() => { break; },
                    _ = interval.tick() => {let _ = sender.send(msg.clone());}
                }
            }
        });

        TickHandler{stop_tx}
    }
}