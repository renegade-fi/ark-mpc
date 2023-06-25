//! Defines an abstraction over the network that receives jobs scheduled onto the
//! network and re-enqueues them in the result buffer for dependent instructions

use tokio::sync::mpsc::{UnboundedReceiver as TokioReceiver, UnboundedSender as TokioSender};

use crate::network::MpcNetwork;

/// The network sender sits behind the scheduler and is responsible for forwarding messages
/// onto the network and pulling results off the network, re-enqueuing them for processing
pub(crate) struct NetworkSender<T: MpcNetwork> {
    /// The outbound queue of messages to send
    outbound: TokioReceiver<()>,
    /// The queue on which to place received messages
    inbound: TokioSender<()>,
    /// The underlying network connection
    network: T,
}

impl<T: MpcNetwork> NetworkSender<T> {
    /// Creates a new network sender
    pub fn new(
        outbound: TokioReceiver<()>,
        inbound: TokioSender<()>,
        network: T,
    ) -> NetworkSender<T> {
        NetworkSender {
            outbound,
            inbound,
            network,
        }
    }

    /// Runs the network sender
    pub async fn run(mut self) {
        loop {
            tokio::select! {
                x = self.outbound.recv() => {
                    // Forward onto the network
                }
            }
        }
    }
}
