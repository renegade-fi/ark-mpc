//! Defines an abstraction over the network that receives jobs scheduled onto
//! the network and re-enqueues them in the result buffer for dependent
//! instructions

use std::fmt::Debug;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

use ark_ec::CurveGroup;
use crossbeam::queue::SegQueue;
use futures::stream::SplitSink;
use futures::SinkExt;
use futures::{stream::SplitStream, StreamExt};
use kanal::AsyncReceiver as KanalReceiver;
use tokio::sync::broadcast::Receiver as BroadcastReceiver;
use tracing::log;

use crate::error::MpcNetworkError;
use crate::network::{MpcNetwork, NetworkOutbound};

use super::executor::ExecutorMessage;
use super::result::OpResult;

/// Error message emitted when a stream closes early
const ERR_STREAM_FINISHED_EARLY: &str = "stream finished early";

// ---------
// | Stats |
// ---------

/// The network stats structs
#[derive(Debug, Default)]
pub struct NetworkStats {
    /// The number of bytes sent
    pub bytes_sent: AtomicUsize,
    /// The number of bytes received
    pub bytes_received: AtomicUsize,
    /// The number of messages sent
    pub messages_sent: AtomicUsize,
    /// The number of messages received
    pub messages_received: AtomicUsize,
}

#[allow(unused)]
impl NetworkStats {
    /// Increment the number of bytes sent
    pub fn increment_bytes_sent(&self, bytes: usize) {
        self.bytes_sent.fetch_add(bytes, std::sync::atomic::Ordering::SeqCst);
    }

    /// Increment the number of bytes received
    pub fn increment_bytes_received(&self, bytes: usize) {
        self.bytes_received.fetch_add(bytes, std::sync::atomic::Ordering::SeqCst);
    }

    /// Increment the number of messages sent
    pub fn increment_messages_sent(&self) {
        self.messages_sent.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Increment the number of messages received
    pub fn increment_messages_received(&self) {
        self.messages_received.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

// -------------------------
// | Sender Implementation |
// -------------------------

/// The network sender sits behind the scheduler and is responsible for
/// forwarding messages onto the network and pulling results off the network,
/// re-enqueuing them for processing
pub(crate) struct NetworkSender<C: CurveGroup, N: MpcNetwork<C>> {
    /// The outbound queue of messages to send
    outbound: KanalReceiver<NetworkOutbound<C>>,
    /// The queue of completed results
    result_queue: Arc<SegQueue<ExecutorMessage<C>>>,
    /// The underlying network connection
    network: N,
    /// The broadcast channel on which shutdown signals are sent
    shutdown: BroadcastReceiver<()>,
}

impl<C: CurveGroup, N: MpcNetwork<C> + 'static> NetworkSender<C, N> {
    /// Creates a new network sender
    pub fn new(
        outbound: KanalReceiver<NetworkOutbound<C>>,
        result_queue: Arc<SegQueue<ExecutorMessage<C>>>,
        network: N,
        shutdown: BroadcastReceiver<()>,
    ) -> Self {
        NetworkSender { outbound, result_queue, network, shutdown }
    }

    /// A helper for the `run` method that allows error handling in the caller
    pub async fn run(self) {
        // Destructure `self` to take ownership of each field
        let NetworkSender { outbound, result_queue, network, mut shutdown } = self;

        // Setup the stats for the network
        let stats = Arc::new(NetworkStats::default());

        // Start a read and write loop separately
        let (send, recv): (SplitSink<N, NetworkOutbound<C>>, SplitStream<N>) = network.split();
        let read_loop_fut = tokio::spawn(Self::read_loop(recv, result_queue, stats.clone()));
        let write_loop_fut = tokio::spawn(Self::write_loop(outbound, send, stats.clone()));

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

        // Log the stats after execution finishes
        #[cfg(feature = "stats")]
        println!("Network stats: {:#?}", stats);
    }

    /// The read loop for the network, reads messages from the network and
    /// re-enqueues them with the executor
    async fn read_loop(
        mut network_stream: SplitStream<N>,
        result_queue: Arc<SegQueue<ExecutorMessage<C>>>,
        #[allow(unused)] stats: Arc<NetworkStats>,
    ) -> MpcNetworkError {
        while let Some(Ok(msg)) = network_stream.next().await {
            #[cfg(feature = "stats")]
            {
                let n_bytes = serde_json::to_vec(&msg).unwrap().len();
                stats.increment_bytes_received(n_bytes);
                stats.increment_messages_received();
            }

            result_queue.push(ExecutorMessage::Result(OpResult {
                id: msg.result_id,
                value: msg.payload.into(),
            }));
        }

        MpcNetworkError::RecvError(ERR_STREAM_FINISHED_EARLY.to_string())
    }

    /// The write loop for the network, reads messages from the outbound queue
    /// and sends them onto the network
    async fn write_loop(
        outbound_stream: KanalReceiver<NetworkOutbound<C>>,
        mut network: SplitSink<N, NetworkOutbound<C>>,
        #[allow(unused)] stats: Arc<NetworkStats>,
    ) -> MpcNetworkError {
        while let Ok(msg) = outbound_stream.recv().await {
            #[cfg(feature = "stats")]
            {
                let n_bytes = serde_json::to_vec(&msg).unwrap().len();
                stats.increment_bytes_sent(n_bytes);
                stats.increment_messages_sent();
            }

            if let Err(e) = network.send(msg).await {
                log::error!("error sending outbound: {e:?}");
                return e;
            }
        }

        MpcNetworkError::RecvError(ERR_STREAM_FINISHED_EARLY.to_string())
    }
}
