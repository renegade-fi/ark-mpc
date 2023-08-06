//! Defines an abstraction over the network that receives jobs scheduled onto the
//! network and re-enqueues them in the result buffer for dependent instructions

use std::sync::Arc;

use crossbeam::queue::SegQueue;
use futures::stream::SplitSink;
use futures::SinkExt;
use futures::{stream::SplitStream, StreamExt};
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tokio::sync::mpsc::UnboundedReceiver as TokioReceiver;
use tracing::log;

use crate::error::MpcNetworkError;
use crate::network::{MpcNetwork, NetworkOutbound};

use super::executor::ExecutorMessage;
use super::result::OpResult;

/// Error message emitted when a stream closes early
const ERR_STREAM_FINISHED_EARLY: &str = "stream finished early";

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

impl<N: MpcNetwork + 'static> NetworkSender<N> {
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
    pub async fn run(self) {
        // Destructure `self` to take ownership of each field
        let NetworkSender {
            outbound,
            result_queue,
            network,
            mut shutdown,
        } = self;

        // Start a read and write loop separately
        let (send, recv) = network.split();
        let read_loop_fut = tokio::spawn(Self::read_loop(recv, result_queue));
        let write_loop_fut = tokio::spawn(Self::write_loop(outbound, send));

        // Await either of the loops to finish or the shutdown signal
        tokio::select! {
            err = read_loop_fut => {
                log::error!("error in `NetworkSender::read_loop`: {err:?}");
            },
            err = write_loop_fut => {
                log::error!("error in `NetworkSender::write_loop`: {err:?}")
            },
            _ = shutdown.recv() => {
                log::info!("received shutdown signal")
            },
        }
    }

    /// The read loop for the network, reads messages from the network and re-enqueues them
    /// with the executor
    async fn read_loop(
        mut network_stream: SplitStream<N>,
        result_queue: Arc<SegQueue<ExecutorMessage>>,
    ) -> MpcNetworkError {
        while let Some(msg) = network_stream.next().await {
            match msg {
                Ok(msg) => {
                    result_queue.push(ExecutorMessage::Result(OpResult {
                        id: msg.result_id,
                        value: msg.payload.into(),
                    }));
                }
                Err(e) => {
                    log::error!("error receiving message: {e}");
                    return e;
                }
            }
        }

        MpcNetworkError::RecvError(ERR_STREAM_FINISHED_EARLY.to_string())
    }

    /// The write loop for the network, reads messages from the outbound queue and sends them
    /// onto the network
    async fn write_loop(
        mut outbound_stream: TokioReceiver<NetworkOutbound>,
        mut network: SplitSink<N, NetworkOutbound>,
    ) -> MpcNetworkError {
        while let Some(msg) = outbound_stream.recv().await {
            if let Err(e) = network.send(msg).await {
                log::error!("error sending outbound: {e:?}");
                return e;
            }
        }

        MpcNetworkError::RecvError(ERR_STREAM_FINISHED_EARLY.to_string())
    }
}
