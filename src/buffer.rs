//! Defines a buffer type used for operations, results, etc in an MPC fabric
//!
//! This buffer allows the creator to pre-allocate buffer space for results to fill, and
//! automatically grows as access to the buffer goes out of bounds

/// A thin wrapper around a vector that auto-allocates as the buffer grows
pub(crate) struct GrowableBuffer<T: Clone> {
    /// The underlying buffer
    buf: Vec<Option<T>>,
}

impl<T: Clone> GrowableBuffer<T> {
    /// Constructor, takes a size-hint to pre-allocate buffer slots
    pub fn new(size_hint: usize) -> Self {
        Self {
            buf: vec![None; size_hint],
        }
    }

    /// Grow the underlying buffer
    fn grow(&mut self, access_idx: usize) {
        let new_size = usize::max(access_idx + 1, self.buf.len() * 2);
        self.buf.resize(new_size, None);
    }

    /// Get the element at the given index in the buffer, returns `None` if the element
    /// has not been set
    pub fn get(&self, idx: usize) -> Option<&T> {
        if idx >= self.buf.len() {
            return None;
        }

        self.buf.get(idx)?.as_ref()
    }

    /// Get an entry as a mutable reference
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut T> {
        if idx >= self.buf.len() {
            self.grow(idx)
        }

        self.buf[idx].as_mut()
    }

    /// Get a mutable reference to the entry at a given index
    pub fn entry_mut(&mut self, idx: usize) -> &mut Option<T> {
        // Grow the buffer if necessary
        if idx >= self.buf.len() {
            self.grow(idx)
        }

        &mut self.buf[idx]
    }

    /// Insert value at the given index
    pub fn insert(&mut self, idx: usize, val: T) -> Option<T> {
        if idx >= self.buf.len() {
            self.grow(idx)
        }

        self.buf.get_mut(idx).unwrap().replace(val)
    }

    /// Take ownership of a value at a given index
    pub fn take(&mut self, idx: usize) -> Option<T> {
        let val = self.buf.get_mut(idx)?;
        val.take()
    }
}

#[cfg(test)]
mod test {
    use super::GrowableBuffer;

    /// Test that indexing into the buffer when it initially has no elements does not fail
    #[test]
    fn test_empty_buf() {
        let mut buf = GrowableBuffer::new(10);
        assert_eq!(buf.get(1), None);

        buf.insert(1, 1);
        assert_eq!(buf.get(1), Some(&1));
    }

    /// Tests that growing a buffer works properly
    #[test]
    fn test_grow_buf() {
        let mut buf: GrowableBuffer<u64> = GrowableBuffer::new(2);
        assert_eq!(buf.get(2), None);

        buf.insert(2, 2);
        assert_eq!(buf.get(2), Some(&2));
    }

    /// Tests getting a mutable reference to an entry
    #[test]
    fn test_mutable_entry() {
        let mut buf: GrowableBuffer<u64> = GrowableBuffer::new(2);
        buf.insert(2, 2);
        *buf.get_mut(2).unwrap() += 1;

        assert_eq!(buf.get(2), Some(&3));
    }

    /// Tests setting a value at an index via the `entry`
    #[test]
    fn test_entry() {
        let mut buf: GrowableBuffer<Vec<u64>> = GrowableBuffer::new(2);
        let entry = buf.entry_mut(0).get_or_insert(vec![]);
        entry.push(1);

        assert_eq!(buf.get(0), Some(&vec![1]));
    }

    /// Tests taking ownership of a value
    #[test]
    fn test_take() {
        let mut buf: GrowableBuffer<u64> = GrowableBuffer::new(2);
        buf.insert(2, 2);

        assert_eq!(buf.take(2), Some(2));
        assert_eq!(buf.get(2), None);
    }
}
