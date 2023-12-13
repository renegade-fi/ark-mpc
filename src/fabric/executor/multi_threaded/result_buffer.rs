//! Contains a concurrent-safe result buffer based on `DashMap` and
//! `AtomicCell`s
//!
//! Laying the `AtomicCell` into the `DashMap` allows us to fully realize the
//! concurrency of the write-once read-many pattern, as we can release the read
//! lock on the `DashMap` immediately and read the value thereafter

use std::sync::Arc;

use ark_ec::CurveGroup;
use bitvec::prelude::*;
use crossbeam::atomic::AtomicCell;
use dashmap::DashMap;
use identity_hash::BuildIdentityHasher;

use crate::{ResultId, ResultValue};

/// An atomic cell wrapping a result
#[allow(type_alias_bounds)]
type AtomicResult<C: CurveGroup> = AtomicCell<ResultValue<C>>;

/// A concurrent safe result buffer
///
/// Our access pattern is write-once read many, so we read by dereferencing
/// raw pointers
#[derive(Clone)]
pub struct ParallelResultBuffer<C: CurveGroup> {
    /// The underlying map
    ///
    /// We use the identity hasher here to emulate the standard single-threaded
    /// buffer Our access pattern is approximately sequential, and mostly
    /// reads so data will naturally be spread out over shards in the
    /// DashMap. As well, using the identity hash removes hashing from the
    /// critical path
    inner: Arc<DashMap<ResultId, AtomicResult<C>, BuildIdentityHasher<ResultId>>>,
}

impl<C: CurveGroup> ParallelResultBuffer<C> {
    /// Constructor
    pub fn new(size_hint: usize) -> Self {
        let n_shards = size_hint.next_power_of_two();
        let inner = DashMap::with_capacity_and_hasher_and_shard_amount(
            size_hint,
            BuildIdentityHasher::default(),
            n_shards,
        );
        Self { inner: Arc::new(inner) }
    }

    /// Get the element at the given index in the buffer, returns `None` if the
    /// element has not been set
    #[allow(unsafe_code)]
    pub fn get(&self, idx: ResultId) -> Option<&ResultValue<C>> {
        let ptr = self.inner.get(&idx)?.value().as_ptr();

        // SAFETY: We only write to a given index once, so this value never changes if
        // it exists
        Some(unsafe { &*ptr })
    }

    /// Set the value at the given index
    ///
    /// Returns the previous value if it existed
    pub fn set(&self, idx: ResultId, val: ResultValue<C>) -> Option<AtomicCell<ResultValue<C>>> {
        self.inner.insert(idx, AtomicResult::new(val))
    }
}

/// An efficient implementation of a mask vector (i.e. `Vec<bool>`) that
/// automatically grows as results are inserted into it
pub struct ResultMask {
    /// The underlying buffer
    buf: BitVec,
}

impl ResultMask {
    /// Constructor
    pub fn new(size_hint: usize) -> Self {
        let buf = bitvec![0; size_hint];
        Self { buf }
    }

    /// Set the value at the given index to true
    pub fn mark_ready(&mut self, id: ResultId) {
        if self.buf.len() <= id {
            self.grow_to(id + 1)
        }

        self.buf.set(id, true);
    }

    /// Get the value at the given index
    pub fn is_ready(&self, id: ResultId) -> bool {
        if self.buf.len() <= id {
            return false;
        }

        self.buf[id]
    }

    /// Grow the vector to at least the given size
    fn grow_to(&mut self, size: usize) {
        // The size should at least double to avoid excessive reallocations
        let new_size = usize::max(self.buf.len() * 2, size);
        self.buf.resize(new_size, false);
        assert_eq!(self.buf.len(), new_size);
    }
}

#[cfg(test)]
mod result_buffer_test {
    use std::thread;

    use rand::{thread_rng, Rng};

    use crate::{algebra::Scalar, test_helpers::TestCurve, ResultValue};

    use super::ParallelResultBuffer;

    /// Get a default buffer
    fn test_buffer() -> ParallelResultBuffer<TestCurve> {
        ParallelResultBuffer::new(10)
    }

    /// Tests a simple get and set
    #[test]
    fn test_get_and_set() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        // Set a random value
        let idx: usize = rng.gen();
        let value = Scalar::random(&mut rng);
        buf.set(idx, ResultValue::Scalar(value));

        // Get the value
        let res = buf.get(idx).unwrap().clone();
        assert_eq!(Scalar::from(res), value);
    }

    /// Tests getting a value that doesn't exist
    #[test]
    fn test_missing_get() {
        let buf = test_buffer();

        // Get a random value
        let idx: usize = thread_rng().gen();
        let res = buf.get(idx);
        assert!(res.is_none());
    }

    /// Tests replacing a value, the original value should be returned
    #[test]
    fn test_replace() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        // Set a random value
        let idx: usize = rng.gen();
        let value = Scalar::random(&mut rng);
        buf.set(idx, ResultValue::Scalar(value));

        // Replace the value
        let new_value = Scalar::random(&mut rng);
        let res = buf.set(idx, ResultValue::Scalar(new_value)).unwrap();
        assert_eq!(Scalar::from(res.into_inner()), value);
    }

    /// Tests data coherence between threads
    #[test]
    fn test_multithreaded_coherence() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        let idx: usize = rng.gen();
        let value = Scalar::random(&mut rng);

        // Set the value in a separate thread
        let buf_clone = buf.clone();
        let jh = thread::spawn(move || {
            buf_clone.set(idx, ResultValue::Scalar(value));
        });
        jh.join().unwrap();

        // Get the value in the main thread
        let res = buf.get(idx).unwrap().clone();
        assert_eq!(Scalar::from(res), value);
    }

    /// Tests that the buffer does not deadlock when inserting a value is
    /// written while a reference to it exists
    ///
    /// Note that this behavior is disallowed, we simply use it to test that
    /// locks are released after a `get`
    #[test]
    fn test_no_deadlock() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        // Set a value
        let idx = rng.gen();
        let value = Scalar::random(&mut rng);
        buf.set(idx, ResultValue::Scalar(value));

        // Get a reference to the value
        let val_ref = buf.get(idx).unwrap();
        assert_eq!(Scalar::from(val_ref.clone()), value);

        // Set the index to a new value while the immutable reference still exists
        let new_value = Scalar::random(&mut rng);
        let old = buf.set(idx, ResultValue::Scalar(new_value)).unwrap();

        // Check that both references are valid
        assert_eq!(Scalar::from(old.into_inner()), value);

        // Get the new value
        let new = buf.get(idx).unwrap();
        assert_eq!(Scalar::from(new.clone()), new_value);
    }
}

#[cfg(test)]
mod result_mask_test {
    use rand::{distributions::uniform::SampleRange, thread_rng};

    use super::ResultMask;

    /// The default mask size for testing
    const DEFAULT_SIZE: usize = 10;

    /// Tests getting a value that has not been set yet
    #[test]
    fn test_unset_value() {
        let mut rng = thread_rng();
        let mask = ResultMask::new(DEFAULT_SIZE);

        // Not set
        let idx = (0..DEFAULT_SIZE).sample_single(&mut rng);
        assert!(!mask.is_ready(idx));

        // Boundary
        let idx = DEFAULT_SIZE;
        assert!(!mask.is_ready(idx));

        // Out of bounds
        assert!(!mask.is_ready(DEFAULT_SIZE + 1));
    }

    /// Tests a simple set and get pattern
    #[test]
    fn test_set_value() {
        let mut rng = thread_rng();
        let mut mask = ResultMask::new(DEFAULT_SIZE);

        // Get the value before it is set
        let idx = (0..DEFAULT_SIZE).sample_single(&mut rng);
        assert!(!mask.is_ready(idx));

        // Set a value
        mask.mark_ready(idx);
        assert!(mask.is_ready(idx));
    }

    /// Tests growing the buffer by setting a value
    #[test]
    fn test_grow_and_get() {
        let mut rng = thread_rng();
        let mut mask = ResultMask::new(DEFAULT_SIZE);

        // Get the value well out of range before it is set
        let idx = (DEFAULT_SIZE * 2..DEFAULT_SIZE * 3).sample_single(&mut rng);
        assert!(!mask.is_ready(idx));

        // Set a value
        mask.mark_ready(idx);
        assert!(mask.is_ready(idx));
    }
}
