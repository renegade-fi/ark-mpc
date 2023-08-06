//! Defines an `std::io::Cursor` like buffer that tracks a cursor within a buffer that
//! is incrementally consumed. We use this to allow partial fills across cancelled
//! futures.
//!
//! This will be replaced when the more convenient `std::io::Cursor` is stabilized.

/// A wrapper around a raw `&[u8]` buffer that tracks a cursor within the buffer
/// to allow partial fills across cancelled futures
///
/// Similar to `tokio::io::ReadBuf` but takes ownership of the underlying buffer to
/// avoid coloring interfaces with lifetime parameters
///
/// TODO: Replace this with `std::io::Cursor` once it is stabilized
#[derive(Debug)]
pub struct BufferWithCursor {
    /// The underlying buffer
    buffer: Vec<u8>,
    /// The current cursor position
    cursor: usize,
}

impl BufferWithCursor {
    /// Create a new buffer with a cursor at the start of the buffer
    pub fn new(buf: Vec<u8>) -> Self {
        assert_eq!(
            buf.len(),
            buf.capacity(),
            "buffer must be fully initialized"
        );

        Self {
            buffer: buf,
            cursor: 0,
        }
    }

    /// The number of bytes remaining in the buffer
    pub fn remaining(&self) -> usize {
        self.buffer.capacity() - self.cursor
    }

    /// Whether the buffer is full
    pub fn is_depleted(&self) -> bool {
        self.remaining() == 0
    }

    /// Get a mutable reference to the empty section of the underlying buffer
    pub fn get_remaining(&mut self) -> &mut [u8] {
        &mut self.buffer[self.cursor..]
    }

    /// Advance the cursor by `n` bytes
    pub fn advance_cursor(&mut self, n: usize) {
        self.cursor += n
    }

    /// Take ownership of the underlying buffer
    pub fn into_vec(self) -> Vec<u8> {
        self.buffer
    }
}
