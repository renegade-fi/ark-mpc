//! Defines an abstraction over the network that receives jobs scheduled onto the
//! network and re-enqueues them in the result buffer for dependent instructions

use std::sync::Arc;

use crossbeam::queue::SegQueue;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::mpsc::UnboundedReceiver as TokioReceiver;
use tracing::log;

use crate::{
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound},
};

use super::executor::ExecutorMessage;
use super::result::OpResult;

// -------------------------
// | Sender Implementation |
// -------------------------

/// The network sender sits behind the scheduler and is responsible for forwarding messages
/// onto the network and pulling results off the network, re-enqueuing them for processing
pub(crate) struct NetworkSender<N: MpcNetwork> {
    /// The outbound queue of messages to send
    outbound: TokioReceiver<NetworkOutbound>,
    /// The queue of completed results
    result_queue: Arc<SegQueue<ExecutorMessage>>,
    /// The underlying network connection
    network: N,
    /// The broadcast channel on which shutdown signals are sent
    shutdown: BroadcastReceiver<()>,
}

impl<N: MpcNetwork> NetworkSender<N> {
    /// Creates a new network sender
    pub fn new(
        outbound: TokioReceiver<NetworkOutbound>,
        result_queue: Arc<SegQueue<ExecutorMessage>>,
        network: N,
        shutdown: BroadcastReceiver<()>,
    ) -> Self {
        NetworkSender {
            outbound,
            result_queue,
            network,
            shutdown,
        }
    }

    /// A helper for the `run` method that allows error handling in the caller
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                // Next outbound message
                x = self.outbound.recv() => {
                    match x {
                        Some(outbound) => {
                            // Forward onto the network
                            if let Err(e) = self.send(outbound).await {
                                log::error!("error sending outbound: {e:?}");
                            }
                        },
                        None => {
                            log::debug!("outbound channel closed, terminating...\n");
                            return;
                        }
                    }

                },

                // Next inbound set of scalars
                res = self.network.receive_message() => {
                    match res {
                        Ok(msg) => self.handle_message(msg).await,

                        Err(e) => {
                            log::error!("error receiving message: {e}");
                            return;
                        }
                    }
                }

                // Shutdown signal from the fabric
                _ = self.shutdown.recv() => {
                    // Close down the network
                    log::debug!("shutdown signal received, terminating...\n");
                    self.network.close().await.expect("error closing network");
                    return;
                }
            }
        }
    }

    /// Sends a message over the network
    async fn send(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        self.network.send_message(message).await
    }

    /// Handle an inbound message
    async fn handle_message(&mut self, message: NetworkOutbound) {
        self.result_queue.push(ExecutorMessage::Result(OpResult {
            id: message.result_id,
            value: message.payload.into(),
        }));
    }
}
