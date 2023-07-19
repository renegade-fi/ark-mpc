//! Defines an MPC fabric for the protocol
//!
//! The fabric essentially acts as a dependency injection layer. That is, the MpcFabric
//! creates and manages dependencies needed to allocate network values. This provides a
//! cleaner interface for consumers of the library; i.e. clients do not have to hold onto
//! references of the network layer or the beaver sources to allocate values.

mod executor;
mod network_sender;
mod result;

#[cfg(feature = "benchmarks")]
pub use executor::{Executor, ExecutorMessage};
#[cfg(not(feature = "benchmarks"))]
use executor::{Executor, ExecutorMessage};
use rand::thread_rng;
pub use result::{cast_args, ResultHandle, ResultId, ResultValue};

use futures::executor::block_on;
use tracing::log;

use std::{
    collections::HashMap,
    fmt::{Debug, Formatter, Result as FmtResult},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex, RwLock,
    },
    task::Waker,
};
use tokio::sync::broadcast::{self, Sender as BroadcastSender};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender as TokioSender};

use itertools::Itertools;

use crate::{
    algebra::{
        authenticated_scalar::AuthenticatedScalarResult,
        authenticated_stark_point::AuthenticatedStarkPointResult,
        mpc_scalar::{MpcScalar, MpcScalarResult},
        mpc_stark_point::{MpcStarkPoint, MpcStarkPointResult},
        scalar::{Scalar, ScalarResult},
        stark_curve::{StarkPoint, StarkPointResult},
    },
    beaver::SharedValueSource,
    network::{MpcNetwork, NetworkOutbound, NetworkPayload, PartyId},
    Shared, PARTY0,
};

use self::{network_sender::NetworkSender, result::OpResult};

/// The result id that is hardcoded to zero
const RESULT_ZERO: ResultId = 0;
/// The result id that is hardcoded to one
const RESULT_ONE: ResultId = 1;
/// The result id that is hardcoded to the curve identity point
const RESULT_IDENTITY: ResultId = 2;
/// The result id that is hardcoded to a shared zero value
const RESULT_ZERO_SHARED: ResultId = 3;
/// The result id that is hardcoded to a shared one value
const RESULT_ONE_SHARED: ResultId = 4;
/// The result id that is hardcoded to a shared curve identity value
const RESULT_IDENTITY_SHARED: ResultId = 5;

/// The number of constant results allocated in the fabric, i.e. those defined above
const N_CONSTANT_RESULTS: usize = 6;

/// An operation within the network, describes the arguments and function to evaluate
/// once the arguments are ready
pub struct Operation {
    /// Identifier of the result that this operation emits
    id: ResultId,
    /// The number of arguments that are still in-flight for this operation
    inflight_args: usize,
    /// The IDs of the inputs to this operation
    args: Vec<ResultId>,
    /// The type of the operation
    op_type: OperationType,
}

impl Debug for Operation {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Operation {}", self.id)
    }
}

/// Defines the different types of operations available in the computation graph
pub enum OperationType {
    /// A gate operation; may be evaluated locally given its ready inputs
    Gate {
        /// The function to apply to the inputs
        function: Box<dyn FnOnce(Vec<ResultValue>) -> ResultValue + Send + Sync>,
    },
    /// A network operation, requires that a value be sent over the network
    Network {
        /// The function to apply to the inputs to derive a Network payload
        function: Box<dyn FnOnce(Vec<ResultValue>) -> NetworkPayload + Send + Sync>,
    },
}

impl Debug for OperationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            OperationType::Gate { .. } => write!(f, "Gate"),
            OperationType::Network { .. } => write!(f, "Network"),
        }
    }
}

/// A fabric for the MPC protocol, defines a dependency injection layer that dynamically schedules
/// circuit gate evaluations onto the network to be executed
///
/// The fabric does not block on gate evaluations, but instead returns a handle to a future result
/// that may be polled to obtain the materialized result. This allows the application layer to
/// continue using the fabric, scheduling more gates to be evaluated and maximally exploiting
/// gate-level parallelism within the circuit
#[derive(Clone)]
pub struct MpcFabric {
    /// The inner fabric
    #[cfg(not(feature = "benchmarks"))]
    inner: FabricInner,
    /// The inner fabric, accessible publicly for benchmark mocking
    #[cfg(feature = "benchmarks")]
    pub inner: FabricInner,
    /// The local party's share of the global MAC key
    ///
    /// The parties collectively hold an additive sharing of the global key
    ///
    /// We wrap in a reference counting structure to avoid recursive type issues
    #[cfg(not(feature = "benchmarks"))]
    mac_key: Option<Arc<MpcScalarResult>>,
    /// The MAC key, accessible publicly for benchmark mocking
    #[cfg(feature = "benchmarks")]
    pub mac_key: Option<Arc<MpcScalarResult>>,
    /// The channel on which shutdown messages are sent to blocking workers
    #[cfg(not(feature = "benchmarks"))]
    shutdown: BroadcastSender<()>,
    /// The shutdown channel, made publicly available for benchmark mocking
    #[cfg(feature = "benchmarks")]
    pub shutdown: BroadcastSender<()>,
}

impl Debug for MpcFabric {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "MpcFabric")
    }
}

/// The inner component of the fabric, allows the constructor to allocate executor and network
/// sender objects at the same level as the fabric
#[derive(Clone)]
pub struct FabricInner {
    /// The ID of the local party in the MPC execution
    party_id: u64,
    /// The next identifier to assign to an operation
    next_id: Arc<AtomicUsize>,
    /// The completed results of operations
    results: Shared<HashMap<ResultId, OpResult>>,
    /// A map of operations to wakers of tasks that are waiting on the operation to complete
    wakers: Shared<HashMap<ResultId, Vec<Waker>>>,
    /// A sender to the executor
    execution_queue: TokioSender<ExecutorMessage>,
    /// The underlying queue to the network
    outbound_queue: TokioSender<NetworkOutbound>,
    /// The underlying shared randomness source
    beaver_source: Arc<Mutex<Box<dyn SharedValueSource>>>,
}

impl Debug for FabricInner {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "FabricInner")
    }
}

impl FabricInner {
    /// Constructor
    pub fn new<S: 'static + SharedValueSource>(
        party_id: u64,
        execution_queue: TokioSender<ExecutorMessage>,
        outbound_queue: TokioSender<NetworkOutbound>,
        beaver_source: S,
    ) -> Self {
        // Allocate a zero and a one as well as the curve identity in the fabric to begin,
        // for convenience
        let zero = ResultValue::Scalar(Scalar::zero());
        let one = ResultValue::Scalar(Scalar::one());
        let identity = ResultValue::Point(StarkPoint::identity());

        let results: HashMap<ResultId, OpResult> = vec![
            (RESULT_ZERO, OpResult { id: 0, value: zero }),
            (RESULT_ONE, OpResult { id: 1, value: one }),
            (
                RESULT_IDENTITY,
                OpResult {
                    id: 2,
                    value: identity,
                },
            ),
        ]
        .into_iter()
        .collect();

        let next_id = Arc::new(AtomicUsize::new(N_CONSTANT_RESULTS));

        Self {
            party_id,
            next_id,
            results: Arc::new(RwLock::new(results)),
            wakers: Arc::new(RwLock::new(HashMap::new())),
            execution_queue,
            outbound_queue,
            beaver_source: Arc::new(Mutex::new(Box::new(beaver_source))),
        }
    }

    /// -----------
    /// | Getters |
    /// -----------

    /// Increment the operation counter and return the existing value
    fn new_id(&self) -> ResultId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Get the hardcoded zero value in the fabric
    pub(crate) fn zero(&self) -> ResultId {
        RESULT_ZERO
    }

    /// Get the hardcoded shared zero value in the fabric
    pub(crate) fn zero_shared(&self) -> ResultId {
        RESULT_ZERO_SHARED
    }

    /// Get the hardcoded one value in the fabric
    pub(crate) fn one(&self) -> ResultId {
        RESULT_ONE
    }

    /// Get the hardcoded shared one value in the fabric
    pub(crate) fn one_shared(&self) -> ResultId {
        RESULT_ONE_SHARED
    }

    /// Get the hardcoded curve identity value in the fabric
    pub(crate) fn curve_identity(&self) -> ResultId {
        RESULT_IDENTITY
    }

    /// Get the hardcoded shared curve identity in the fabric
    pub(crate) fn curve_identity_shared(&self) -> ResultId {
        RESULT_IDENTITY_SHARED
    }

    // ------------------------
    // | Low Level Allocation |
    // ------------------------

    /// Set a result directly, prefer to use allocation methods below for safety
    pub(crate) fn set_result(&self, id: ResultId, value: ResultValue) -> ResultId {
        // Acquire locks and update the result buffer
        let mut locked_results = self.results.write().expect("results poisoned");
        locked_results.insert(id, OpResult { id, value });

        id
    }

    /// Allocate a new plaintext value in the fabric
    pub(crate) fn allocate_value(&self, value: ResultValue) -> ResultId {
        // Acquire locks
        let mut locked_results = self.results.write().expect("results poisoned");

        // Update fabric state
        let id = self.new_id();
        locked_results.insert(id, OpResult { id, value });

        id
    }

    /// Allocate a secret shared value in the network
    pub(crate) fn allocate_shared_value(
        &self,
        my_share: ResultValue,
        their_share: ResultValue,
    ) -> ResultId {
        // Acquire locks
        let mut locked_results = self.results.write().expect("results poisoned");

        // Add my share to the results
        let id = self.new_id();
        locked_results.insert(
            id,
            OpResult {
                id,
                value: my_share,
            },
        );

        // Send the counterparty their share
        if let Err(e) = self.outbound_queue.send(NetworkOutbound {
            op_id: id,
            payload: their_share.into(),
        }) {
            log::error!("error sending share to counterparty: {e:?}");
        }

        id
    }

    /// Receive a value from a network operation initiated by a peer
    ///
    /// The peer will already send the value with the corresponding ID, so all that is needed
    /// is to allocate a slot in the result buffer for the receipt
    pub(crate) fn receive_value(&self) -> ResultId {
        self.new_id()
    }

    // --------------
    // | Operations |
    // --------------

    /// Allocate a new in-flight gate operation in the fabric
    pub(crate) fn new_op(&self, args: Vec<ResultId>, op_type: OperationType) -> ResultId {
        // Get an ID for the result
        let id = self.new_id();
        self.execution_queue
            .send(ExecutorMessage::Op { id, args, op_type })
            .expect("executor channel closed");

        id
    }
}

impl MpcFabric {
    /// Constructor
    pub fn new<N: 'static + MpcNetwork, S: 'static + SharedValueSource>(
        network: N,
        beaver_source: S,
    ) -> Self {
        // Build communication primitives
        let (result_sender, result_receiver) = unbounded_channel();
        let (outbound_sender, outbound_receiver) = unbounded_channel();
        let (shutdown_sender, shutdown_receiver) = broadcast::channel(1 /* capacity */);

        // Build a fabric
        let fabric = FabricInner::new(
            network.party_id(),
            result_sender.clone(),
            outbound_sender,
            beaver_source,
        );

        // Start a network sender and operator executor
        let network_sender = NetworkSender::new(
            outbound_receiver,
            result_sender.clone(),
            network,
            shutdown_receiver,
        );
        tokio::task::spawn_blocking(move || block_on(network_sender.run()));

        let executor = Executor::new(
            result_receiver,
            result_sender,
            fabric.clone(),
            shutdown_sender.subscribe(),
        );
        tokio::task::spawn_blocking(move || block_on(executor.run()));

        // Create the fabric and fill in the MAC key after
        let mut self_ = Self {
            inner: fabric.clone(),
            shutdown: shutdown_sender,
            mac_key: None,
        };

        // Create shared constants for zero, one, and the curve identity
        fabric.set_result(
            RESULT_ZERO_SHARED,
            ResultValue::MpcScalar(MpcScalar {
                value: Scalar::zero(),
                fabric: self_.clone(),
            }),
        );
        fabric.set_result(
            RESULT_ONE_SHARED,
            ResultValue::MpcScalar(MpcScalar {
                value: if self_.party_id() == PARTY0 {
                    Scalar::zero()
                } else {
                    Scalar::one()
                },
                fabric: self_.clone(),
            }),
        );
        fabric.set_result(
            RESULT_IDENTITY_SHARED,
            ResultValue::MpcStarkPoint(MpcStarkPoint {
                value: StarkPoint::identity(),
                fabric: self_.clone(),
            }),
        );

        // Sample a MAC key from the pre-shared values in the beaver source
        let mac_key_id = fabric.allocate_value(ResultValue::Scalar(
            fabric
                .beaver_source
                .lock()
                .expect("beaver source poisoned")
                .next_shared_value(),
        ));
        let mac_key = MpcScalarResult::new_shared(ResultHandle::new(mac_key_id, self_.clone()));

        // Set the MAC key
        self_.mac_key.replace(Arc::new(mac_key));

        self_
    }

    /// Get the party ID of the local party
    pub fn party_id(&self) -> PartyId {
        self.inner.party_id
    }

    /// Shutdown the fabric and the threads it has spawned
    pub fn shutdown(self) {
        log::debug!("shutting down fabric");
        self.shutdown
            .send(())
            .expect("error sending shutdown signal");
    }

    /// Immutably borrow the MAC key
    pub(crate) fn borrow_mac_key(&self) -> &MpcScalarResult {
        // Unwrap is safe, the constructor sets the MAC key
        self.mac_key.as_ref().unwrap()
    }

    // ------------------------
    // | Constants Allocation |
    // ------------------------

    /// Get the hardcoded zero wire as a raw `ScalarResult`
    pub fn zero(&self) -> ScalarResult {
        ResultHandle::new(self.inner.zero(), self.clone())
    }

    /// Get the shared zero value as an `MpcScalarResult`
    fn zero_shared(&self) -> MpcScalarResult {
        ResultHandle::new(self.inner.zero_shared(), self.clone())
    }

    /// Get the hardcoded zero wire as an `AuthenticatedScalarResult`
    ///
    /// Both parties hold the share 0 directly in this case
    pub fn zero_authenticated(&self) -> AuthenticatedScalarResult {
        let zero_value = self.zero();
        let share_value = self.zero_shared();
        let mac_value = self.zero_shared();

        AuthenticatedScalarResult {
            value: share_value,
            mac: mac_value,
            public_modifier: zero_value,
            fabric: self.clone(),
        }
    }

    /// Get a batch of references to the zero wire as an `AuthenticatedScalarResult`
    pub fn zeros_authenticated(&self, n: usize) -> Vec<AuthenticatedScalarResult> {
        let val = self.zero_authenticated();
        (0..n).map(|_| val.clone()).collect_vec()
    }

    /// Get the hardcoded one wire as a raw `ScalarResult`
    pub fn one(&self) -> ScalarResult {
        ResultHandle::new(self.inner.one(), self.clone())
    }

    /// Get the hardcoded shared one wire as an `MpcScalarResult`
    fn one_shared(&self) -> MpcScalarResult {
        ResultHandle::new(self.inner.one_shared(), self.clone())
    }

    /// Get the hardcoded one wire as an `AuthenticatedScalarResult`
    ///
    /// Party 0 holds the value zero and party 1 holds the value one
    pub fn one_authenticated(&self) -> AuthenticatedScalarResult {
        if self.party_id() == PARTY0 {
            let zero_value = self.zero();
            let share_value = self.zero_shared();
            let mac_value = self.zero_shared();

            AuthenticatedScalarResult {
                value: share_value,
                mac: mac_value,
                public_modifier: zero_value,
                fabric: self.clone(),
            }
        } else {
            let zero_value = self.zero();
            let share_value = self.one_shared();
            let mac_value = self.borrow_mac_key().clone();

            AuthenticatedScalarResult {
                value: share_value,
                mac: mac_value,
                public_modifier: zero_value,
                fabric: self.clone(),
            }
        }
    }

    /// Get a batch of references to the one wire as an `AuthenticatedScalarResult`
    pub fn ones_authenticated(&self, n: usize) -> Vec<AuthenticatedScalarResult> {
        let val = self.one_authenticated();
        (0..n).map(|_| val.clone()).collect_vec()
    }

    /// Get the hardcoded curve identity wire as a raw `StarkPoint`
    pub fn curve_identity(&self) -> ResultHandle<StarkPoint> {
        ResultHandle::new(self.inner.curve_identity(), self.clone())
    }

    /// Get the hardcoded shared curve identity wire as an `MpcStarkPointResult`
    fn curve_identity_shared(&self) -> MpcStarkPointResult {
        ResultHandle::new(self.inner.curve_identity_shared(), self.clone())
    }

    /// Get the hardcoded curve identity wire as an `AuthenticatedStarkPointResult`
    ///
    /// Both parties hold the identity point directly in this case
    pub fn curve_identity_authenticated(&self) -> AuthenticatedStarkPointResult {
        let identity_val = self.curve_identity();
        let share_value = self.curve_identity_shared();
        let mac_value = self.curve_identity_shared();

        AuthenticatedStarkPointResult {
            value: share_value,
            mac: mac_value,
            public_modifier: identity_val,
            fabric: self.clone(),
        }
    }

    // -------------------
    // | Wire Allocation |
    // -------------------

    /// Allocate a new plaintext value in the fabric
    pub fn allocate_value<T: From<ResultValue>>(&self, value: ResultValue) -> ResultHandle<T> {
        let id = self.inner.allocate_value(value);
        ResultHandle::new(id, self.clone())
    }

    /// Allocate a shared value in the fabric
    pub fn allocate_shared_value<T: From<ResultValue>>(
        &self,
        my_share: ResultValue,
        their_share: ResultValue,
    ) -> ResultHandle<T> {
        let id = self.inner.allocate_shared_value(my_share, their_share);
        ResultHandle::new(id, self.clone())
    }

    /// Share a `Scalar` value with the counterparty
    pub fn share_scalar<T: Into<Scalar>>(
        &self,
        val: T,
        sender: PartyId,
    ) -> AuthenticatedScalarResult {
        let scalar: ScalarResult = if self.party_id() == sender {
            let scalar_val = val.into();
            let mut rng = thread_rng();
            let random = Scalar::random(&mut rng);

            let (my_share, their_share) = (scalar_val - random, random);
            self.allocate_shared_value(
                ResultValue::Scalar(my_share),
                ResultValue::Scalar(their_share),
            )
        } else {
            self.receive_value()
        };

        AuthenticatedScalarResult::new_shared(scalar)
    }

    /// Share a `StarkPoint` value with the counterparty
    pub fn share_point(&self, val: StarkPoint, sender: PartyId) -> AuthenticatedStarkPointResult {
        let point: StarkPointResult = if self.party_id() == sender {
            // As mentioned in https://eprint.iacr.org/2009/226.pdf
            // it is okay to sample a random point by sampling a random `Scalar` and multiplying
            // by the generator in the case that the discrete log of the output may be leaked with
            // respect to the generator. Leaking the discrete log (i.e. the random `Scalar`) is okay
            // when it is used to generate secret shares
            let mut rng = thread_rng();
            let random = Scalar::random(&mut rng);
            let random_point = random * StarkPoint::generator();

            let (my_share, their_share) = (val - random_point, random_point);
            self.allocate_shared_value(
                ResultValue::Point(my_share),
                ResultValue::Point(their_share),
            )
        } else {
            self.receive_value()
        };

        AuthenticatedStarkPointResult::new_shared(point)
    }

    /// Allocate a public value in the fabric
    pub fn allocate_scalar<T: Into<Scalar>>(&self, value: T) -> ResultHandle<Scalar> {
        self.allocate_value(ResultValue::Scalar(value.into()))
    }

    /// Allocate a scalar as a secret share of an already shared value
    pub fn allocate_preshared_scalar<T: Into<Scalar>>(
        &self,
        value: T,
    ) -> AuthenticatedScalarResult {
        let allocated = self.allocate_scalar(value);
        AuthenticatedScalarResult::new_shared(allocated)
    }

    /// Allocate a public curve point in the fabric
    pub fn allocate_point(&self, value: StarkPoint) -> ResultHandle<StarkPoint> {
        self.allocate_value(ResultValue::Point(value))
    }

    /// Send a value to the peer, placing the identity in the local result buffer at the send ID
    pub fn send_value<T: From<ResultValue> + Into<NetworkPayload>>(
        &self,
        value: ResultHandle<T>,
    ) -> ResultHandle<T> {
        self.new_network_op(vec![value.id], |args| {
            let [value]: [T; 1] = cast_args(args);
            value.into()
        })
    }

    /// Send a `Scalar` that has not been previously allocated in the mpc fabric
    pub fn send_scalar<T: Into<Scalar>>(&self, value: T) -> ResultHandle<Scalar> {
        let scalar: Scalar = value.into();
        self.new_network_op(vec![], move |_args| scalar.into())
    }

    /// Receive a value from the peer
    pub fn receive_value<T: From<ResultValue>>(&self) -> ResultHandle<T> {
        let id = self.inner.receive_value();
        ResultHandle::new(id, self.clone())
    }

    /// Exchange a value with the peer, i.e. send then receive or receive then send
    /// based on the party ID
    ///
    /// Returns a handle to the received value, which will be different for different parties
    pub fn exchange_value<T: From<ResultValue> + Into<NetworkPayload>>(
        &self,
        value: ResultHandle<T>,
    ) -> ResultHandle<T> {
        if self.party_id() == PARTY0 {
            // Party 0 sends first then receives
            self.send_value(value);
            self.receive_value()
        } else {
            // Party 1 receives first then sends
            let handle = self.receive_value();
            self.send_value(value);
            handle
        }
    }

    // -------------------
    // | Gate Definition |
    // -------------------

    /// Construct a new gate operation in the fabric, i.e. one that can be evaluated immediate given
    /// its inputs
    pub fn new_gate_op<F, T>(&self, args: Vec<ResultId>, function: F) -> ResultHandle<T>
    where
        F: 'static + FnOnce(Vec<ResultValue>) -> ResultValue + Send + Sync,
        T: From<ResultValue>,
    {
        let function = Box::new(function);
        let id = self.inner.new_op(args, OperationType::Gate { function });
        ResultHandle::new(id, self.clone())
    }

    /// Construct a new network operation in the fabric, i.e. one that requires a value to be sent
    /// over the channel
    pub fn new_network_op<F, T>(&self, args: Vec<ResultId>, function: F) -> ResultHandle<T>
    where
        F: 'static + FnOnce(Vec<ResultValue>) -> NetworkPayload + Send + Sync,
        T: From<ResultValue>,
    {
        let function = Box::new(function);
        let id = self.inner.new_op(args, OperationType::Network { function });
        ResultHandle::new(id, self.clone())
    }

    // -----------------
    // | Beaver Source |
    // -----------------

    /// Sample the next beaver triplet from the beaver source
    pub fn next_beaver_triple(&self) -> (MpcScalarResult, MpcScalarResult, MpcScalarResult) {
        // Sample the triple and allocate it in the fabric, the counterparty will do the same
        let (a, b, c) = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_triplet();

        let a_val = self.allocate_value(ResultValue::Scalar(a));
        let b_val = self.allocate_value(ResultValue::Scalar(b));
        let c_val = self.allocate_value(ResultValue::Scalar(c));

        (
            MpcScalarResult::new_shared(a_val),
            MpcScalarResult::new_shared(b_val),
            MpcScalarResult::new_shared(c_val),
        )
    }

    /// Sample the next beaver triplet with MACs from the beaver source
    ///
    /// TODO: Authenticate these values either here or in the pre-processing phase as per
    /// the SPDZ paper
    pub fn next_authenticated_beaver_triple(
        &self,
    ) -> (
        AuthenticatedScalarResult,
        AuthenticatedScalarResult,
        AuthenticatedScalarResult,
    ) {
        let (a, b, c) = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_triplet();

        let a_val = self.allocate_value(ResultValue::Scalar(a));
        let b_val = self.allocate_value(ResultValue::Scalar(b));
        let c_val = self.allocate_value(ResultValue::Scalar(c));

        (
            AuthenticatedScalarResult::new_shared(a_val),
            AuthenticatedScalarResult::new_shared(b_val),
            AuthenticatedScalarResult::new_shared(c_val),
        )
    }

    /// Sample a batch of random shared values from the beaver source
    pub fn random_shared_scalars(&self, n: usize) -> Vec<ScalarResult> {
        let values_raw = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_shared_value_batch(n);

        // Wrap the values in a result handle
        values_raw
            .into_iter()
            .map(|value| self.allocate_value(ResultValue::Scalar(value)))
            .collect_vec()
    }

    /// Sample a batch of random shared values from the beaver source and allocate them as `AuthenticatedScalars`
    pub fn random_shared_scalars_authenticated(&self, n: usize) -> Vec<AuthenticatedScalarResult> {
        let values_raw = self
            .inner
            .beaver_source
            .lock()
            .expect("beaver source poisoned")
            .next_shared_value_batch(n);

        // Wrap the values in an authenticated wrapper
        values_raw
            .into_iter()
            .map(|value| {
                let value = self.allocate_value(ResultValue::Scalar(value));
                AuthenticatedScalarResult::new_shared(value)
            })
            .collect_vec()
    }
}
