//! Contains an implementation of a mask vector (i.e. `Vec<bool>`) that grows
//! automatically as new results are inserted into it

use crate::ResultId;
use bitvec::prelude::*;

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
