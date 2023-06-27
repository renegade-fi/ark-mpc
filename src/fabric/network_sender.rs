//! Defines an abstraction over the network that receives jobs scheduled onto the
//! network and re-enqueues them in the result buffer for dependent instructions

use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender};
use tracing::log;

use crate::{
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound, QuicTwoPartyNet},
};

use super::result::OpResult;

// -------------
// | Constants |
// -------------

/// The amount of time to wait in between

/// The error message emitted when sending a value to the result queue fails
const ERR_SEND_FAILURE: &str = "error sending value";

// -------------------------
// | Sender Implementation |
// -------------------------

/// The network sender sits behind the scheduler and is responsible for forwarding messages
/// onto the network and pulling results off the network, re-enqueuing them for processing
pub(crate) struct NetworkSender {
    /// The outbound queue of messages to send
    outbound: TokioReceiver<NetworkOutbound>,
    /// The queue of completed results
    result_queue: TokioSender<OpResult>,
    /// The underlying network connection
    network: QuicTwoPartyNet,
    /// The broadcast channel on which shutdown signals are sent
    shutdown: BroadcastReceiver<()>,
}

impl NetworkSender {
    /// Creates a new network sender
    pub fn new(
        outbound: TokioReceiver<NetworkOutbound>,
        result_queue: TokioSender<OpResult>,
        network: QuicTwoPartyNet,
        shutdown: BroadcastReceiver<()>,
    ) -> NetworkSender {
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
                    // Forward onto the network
                    if let Err(e) = self.send(x.unwrap()).await {
                        log::error!("error sending outbound: {e:?}");
                    }
                },

                // Next inbound set of scalars
                res = self.network.receive_message() => {
                    match res {
                        Ok(msg) => {
                            if let Err(e) = self.handle_message(msg).await {
                                log::error!("error handling message: {e}");
                                return;
                            }
                        },

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
    async fn handle_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        self.result_queue
            .send(OpResult {
                id: message.op_id,
                value: message.payload,
            })
            .map_err(|_| MpcNetworkError::SendError(ERR_SEND_FAILURE.to_string()))
    }
}
