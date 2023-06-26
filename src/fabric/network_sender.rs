//! Defines an abstraction over the network that receives jobs scheduled onto the
//! network and re-enqueues them in the result buffer for dependent instructions

use tokio::sync::mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender};
use tracing::log;

use crate::{
    error::MpcNetworkError,
    network::{MpcNetwork, NetworkOutbound},
};

// -------------
// | Constants |
// -------------

const ERR_SEND_FAILURE: &str = "error sending value";

// -------------------------
// | Sender Implementation |
// -------------------------

/// The network sender sits behind the scheduler and is responsible for forwarding messages
/// onto the network and pulling results off the network, re-enqueuing them for processing
pub(crate) struct NetworkSender<T: MpcNetwork> {
    /// The outbound queue of messages to send
    outbound: TokioReceiver<NetworkOutbound>,
    /// The queue on which to place received messages
    inbound: TokioSender<()>,
    /// The underlying network connection
    network: T,
}

impl<T: MpcNetwork> NetworkSender<T> {
    /// Creates a new network sender
    pub fn new(
        outbound: TokioReceiver<NetworkOutbound>,
        inbound: TokioSender<()>,
        network: T,
    ) -> NetworkSender<T> {
        NetworkSender {
            outbound,
            inbound,
            network,
        }
    }

    /// A helper for the `run` method that allows error handling in the caller
    async fn run(mut self) {
        loop {
            tokio::select! {
                // Next outbound message
                x = self.outbound.recv() => {
                    // Forward onto the network
                    self.send(x.unwrap()).await.expect(ERR_SEND_FAILURE);
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
            }
        }
    }

    /// Sends a message over the network
    async fn send(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        self.network.send_message(message).await
    }

    /// Handle an inbound message
    async fn handle_message(&mut self, message: NetworkOutbound) -> Result<(), MpcNetworkError> {
        todo!()
    }
}
