//! Defines a buffer for storing the results of a multi-threaded executor
//!
//! The design of the buffer is specifically tailored to the application via the
//! following assumptions it is aware of:
//! - A given entry in the buffer is only ever written once
//! - Values are only read after they are written, meaning a separate mechanism
//!   accounts values as being written
//! - The size of the buffer may not be known when it is allocated
//!
//! As a result we use a linked list of shard vectors to store the results. Each
//! vector holds `AtomicCell`s that may be dereferenced directly to get the
//! result. The linked list allows us to grow the buffer as needed without
//! needing to copy the existing results or reallocate the entire buffer
//!
//! The size hint passed into the constructor should be used to tailor the size
//! of the buffer to the expected number of results. This is used to
//! pre-allocate the first shard vector. Performance sensitive applications
//! with static MPC circuits can measure the number of results and then allocate
//! exactly that sized buffer to avoid re-allocation entirely

use std::sync::{
    atomic::{AtomicU32, Ordering},
    Arc, Mutex,
};

use ark_ec::CurveGroup;
use crossbeam::atomic::AtomicCell;

use crate::{ResultId, ResultValue};

/// A shard in the buffer, represents a consecutive range of results in memory
struct BufferShard<C: CurveGroup> {
    /// The underlying vector
    inner: Vec<AtomicResult<C>>,
    /// The next shard in the buffer
    next_shard: Box<AtomicCell<NextPtr<C>>>,
}

impl<C: CurveGroup> BufferShard<C> {
    /// Constructor
    fn new(shard_size: usize) -> Self {
        let inner = (0..shard_size).map(|_| AtomicCell::new(None)).collect();
        Self { inner, next_shard: Box::new(AtomicCell::new(None)) }
    }

    /// Get the next shard in the buffer
    #[allow(unsafe_code)]
    fn next_shard(&self) -> Option<&BufferShard<C>> {
        unsafe { self.next_shard.as_ptr().as_ref().unwrap().as_ref() }
    }

    /// Get the value at the given index
    ///
    /// SAFETY: The value is only written once
    #[allow(unsafe_code)]
    fn get(&self, idx: ResultId) -> Option<&ResultValue<C>> {
        unsafe { self.inner[idx].as_ptr().as_ref().unwrap().as_ref() }
    }

    /// Set the value at the given index
    ///
    /// SAFETY: The value is only written once
    #[allow(unsafe_code)]
    fn set(&self, idx: ResultId, val: ResultValue<C>) -> Option<ResultValue<C>> {
        let val_ref = self.inner[idx].as_ptr();
        unsafe { (*val_ref).replace(val) }
    }
}

/// An atomic cell wrapping a result
#[allow(type_alias_bounds)]
type AtomicResult<C: CurveGroup> = AtomicCell<Option<ResultValue<C>>>;
/// A type alias for the next pointer in an intrusive linked list of buffer
/// shards
type NextPtr<C> = Option<BufferShard<C>>;

/// A buffer, comprised of a linked list of shards, each of the size given by
/// the hint
#[derive(Clone)]
pub struct ParallelResultBuffer<C: CurveGroup> {
    /// The head of the buffer
    head: Arc<BufferShard<C>>,
    /// The number of shards in the buffer  
    n_shards: Arc<AtomicU32>,
    /// The size of shards in the buffer
    shard_size: usize,
    /// A lock for growing the buffer
    grow_lock: Arc<Mutex<()>>,
}

impl<C: CurveGroup> ParallelResultBuffer<C> {
    /// Constructor
    pub fn new(size_hint: usize) -> Self {
        let inner = BufferShard::new(size_hint);

        Self {
            head: Arc::new(inner),
            n_shards: Arc::new(AtomicU32::new(1)),
            shard_size: size_hint,
            grow_lock: Arc::new(Mutex::new(())),
        }
    }

    /// Get a value from the buffer
    pub fn get(&self, idx: ResultId) -> Option<&ResultValue<C>> {
        // Seek to the shard
        let (shard_id, idx) = self.get_shard_and_offset(idx);
        let shard = self.seek_to_shard(shard_id)?;

        // Get the value
        shard.get(idx)
    }

    /// Set the value at the given index
    ///
    /// Returns the previous value if it existed
    pub fn set(&self, idx: ResultId, val: ResultValue<C>) {
        // Seek to the shard
        let (shard_id, offset) = self.get_shard_and_offset(idx);
        let shard = match self.seek_to_shard(shard_id) {
            Some(shard) => shard,
            None => self.grow_to_n_shards(shard_id + 1),
        };

        // Set the value
        let prev = shard.set(offset, val);
        debug_assert!(prev.is_none());
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the shard that stores a given index and the offset of the index in
    /// that shard
    fn get_shard_and_offset(&self, idx: ResultId) -> (usize, usize) {
        let shard_size = self.shard_size;
        let shard_idx = idx / shard_size;
        let offset = idx % shard_size;

        (shard_idx, offset)
    }

    /// Seek to a given shard
    ///
    /// SAFETY: The `next_shard` pointer is only ever written once, so this
    /// value never changes if it exists
    fn seek_to_shard(&self, shard_idx: usize) -> Option<&BufferShard<C>> {
        let mut shard = self.head.as_ref();
        for _ in 0..shard_idx {
            shard = shard.next_shard()?;
        }

        Some(shard)
    }

    /// Grow the buffer to a size of `n` shards
    ///
    /// Returns the new last shard
    fn grow_to_n_shards(&self, n: usize) -> &BufferShard<C> {
        let _guard = self.grow_lock.lock().unwrap();
        // After exiting the guard, check if the buffer has already been grown
        // sufficiently
        let curr_shards = self.n_shards.load(Ordering::Relaxed) as usize;
        if curr_shards >= n {
            return self.seek_to_shard(n - 1).unwrap();
        }

        // Seek to the last shard
        let mut shard = self.seek_to_shard(curr_shards - 1).unwrap();

        // Grow the buffer
        for _ in curr_shards..n {
            let new_shard = BufferShard::new(self.shard_size);
            shard.next_shard.store(Some(new_shard));
            shard = shard.next_shard().unwrap();
        }

        // Set the new number of shards
        self.n_shards.store(n as u32, Ordering::Relaxed);
        shard
    }
}

#[cfg(test)]
mod test {
    use std::{collections::HashSet, thread};

    use itertools::Itertools;
    use rand::{distributions::uniform::SampleRange, thread_rng, Rng};

    use crate::{algebra::Scalar, test_helpers::TestCurve, ResultValue};

    use super::ParallelResultBuffer;

    /// The default size to allocate for the buffer
    const DEFAULT_SIZE: usize = 10;

    /// Create a test buffer of default size
    fn test_buffer() -> ParallelResultBuffer<TestCurve> {
        ParallelResultBuffer::new(DEFAULT_SIZE)
    }

    /// Tests a simple get and set pattern
    #[test]
    fn test_get_and_set() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        let idx = rng.gen_range(0..DEFAULT_SIZE);
        let val = Scalar::<TestCurve>::random(&mut rng);

        // Get the value at the index
        assert!(buf.get(idx).is_none());

        // Set the value
        buf.set(idx, ResultValue::Scalar(val));

        // Get the value again
        let res = buf.get(idx).unwrap().clone();
        assert_eq!(Scalar::from(res), val);
    }

    /// Tests various ways of getting values that are not present
    #[test]
    fn test_missing_value() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        // A random index not yet set
        let idx = rng.gen_range(DEFAULT_SIZE..2 * DEFAULT_SIZE);
        assert!(buf.get(idx).is_none());

        // A boundary index
        assert!(buf.get(DEFAULT_SIZE).is_none());

        // A random out of bounds index
        let idx = rng.gen_range(2 * DEFAULT_SIZE..3 * DEFAULT_SIZE);
        assert!(buf.get(idx).is_none());
    }

    /// Tests growing the buffer to multiple shards and then getting all values
    #[test]
    fn test_grow_and_get() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        const N: usize = DEFAULT_SIZE * 4;
        let values = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();
        for (idx, value) in (0..N).zip(values.iter().copied()) {
            buf.set(idx, ResultValue::Scalar(value));
        }

        // Check all values
        for (idx, expected_value) in (0..N).zip(values) {
            let res = buf.get(idx).unwrap().clone();
            assert_eq!(Scalar::from(res), expected_value);
        }
    }

    /// Tests setting a value that requires growing multiple shards
    #[test]
    fn test_grow_multi() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        // Set a value well outside of the current capacity
        let idx = (5 * DEFAULT_SIZE..10 * DEFAULT_SIZE).sample_single(&mut rng);
        let value = Scalar::random(&mut rng);

        buf.set(idx, ResultValue::Scalar(value));

        // Get the value
        let res = buf.get(idx).unwrap();
        assert_eq!(Scalar::from(res), value)
    }

    /// Tests setting and getting a bunch of values randomly
    #[test]
    fn test_set_and_get_random() {
        const N: usize = 1000;
        const MAX_IDX: usize = DEFAULT_SIZE * 100;
        let mut rng = thread_rng();
        let buf = test_buffer();

        // Use a hash set to ensure the indices are unique
        let indices: HashSet<usize> = (0..N).map(|_| rng.gen_range(0..MAX_IDX)).collect();
        for index in indices.iter().copied() {
            let value = Scalar::from(index);
            buf.set(index, ResultValue::Scalar(value));
        }

        // Check all values
        for index in indices {
            let value = Scalar::from(index);
            let res = buf.get(index).unwrap().clone();
            assert_eq!(Scalar::from(res), value);
        }
    }

    /// Tests data coherence between threads
    #[test]
    fn test_multithreaded_coherence() {
        let mut rng = thread_rng();
        let buf = test_buffer();

        let idx = (2 * DEFAULT_SIZE..3 * DEFAULT_SIZE).sample_single(&mut rng);
        let value = Scalar::random(&mut rng);

        // Set the value in a separate thread
        let buf_clone = buf.clone();
        let jh = thread::spawn(move || {
            buf_clone.set(idx, ResultValue::Scalar(value));
        });
        jh.join().unwrap();

        // Get the value in the main thread
        let res = buf.get(idx).unwrap();
        assert_eq!(Scalar::from(res), value);
    }
}
