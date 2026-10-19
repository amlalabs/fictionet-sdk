use core::cmp;
use managed::ManagedSlice;

/// A byte ring for TCP receive and send buffers.
/// Storage may be borrowed or owned. Slices can cross the end of the ring.
#[derive(Debug)]
pub struct RingBuffer<'a> {
    storage: ManagedSlice<'a, u8>,
    read_at: usize,
    length: usize,
}

impl<'a> RingBuffer<'a> {
    /// Create a ring buffer with the given storage.
    ///
    pub fn new<S>(storage: S) -> RingBuffer<'a>
    where
        S: Into<ManagedSlice<'a, u8>>,
    {
        RingBuffer {
            storage: storage.into(),
            read_at: 0,
            length: 0,
        }
    }

    /// Clear the ring buffer.
    pub(crate) fn clear(&mut self) {
        self.read_at = 0;
        self.length = 0;
    }

    /// Return the maximum number of elements in the ring buffer.
    pub(crate) fn capacity(&self) -> usize {
        self.storage.len()
    }

    /// Return the current number of elements in the ring buffer.
    pub(crate) fn len(&self) -> usize {
        self.length
    }

    /// Return the number of elements that can be added to the ring buffer.
    pub(crate) fn window(&self) -> usize {
        self.capacity() - self.len()
    }

    /// Return the largest number of elements that can be added to the buffer
    /// without wrapping around.
    pub(crate) fn contiguous_window(&self) -> usize {
        cmp::min(self.window(), self.capacity() - self.get_idx(self.length))
    }

    /// Query whether the buffer is empty.
    pub(crate) fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Shorthand for `(self.read + idx) % self.capacity()` with an
    /// additional check to ensure that the capacity is not zero.
    fn get_idx(&self, idx: usize) -> usize {
        let len = self.capacity();
        if len > 0 {
            (self.read_at + idx) % len
        } else {
            0
        }
    }
}

/// This is the "continuous" ring buffer interface: it operates with element slices,
/// and boundary conditions (empty/full) simply result in empty slices.
impl<'a> RingBuffer<'a> {
    /// Call `f` with the largest contiguous slice of unallocated buffer elements,
    /// and enqueue the amount of elements returned by `f`.
    ///
    /// # Panics
    /// This function panics if the amount of elements returned by `f` is larger
    /// than the size of the slice passed into it.
    pub(crate) fn enqueue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        if self.length == 0 {
            // Ring is currently empty. Reset `read_at` to optimize
            // for contiguous space.
            self.read_at = 0;
        }

        let write_at = self.get_idx(self.length);
        let max_size = self.contiguous_window();
        let (size, result) = f(&mut self.storage[write_at..write_at + max_size]);
        assert!(size <= max_size);
        self.length += size;
        (size, result)
    }

    /// Enqueue as many elements from the given slice into the buffer as possible,
    /// and return the amount of elements that could fit.
    #[must_use]
    pub(crate) fn enqueue_slice(&mut self, data: &[u8]) -> usize {
        let (size_1, data) = self.enqueue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            buf[..size].copy_from_slice(&data[..size]);
            (size, &data[size..])
        });
        let (size_2, ()) = self.enqueue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            buf[..size].copy_from_slice(&data[..size]);
            (size, ())
        });
        size_1 + size_2
    }

    /// Call `f` with the largest contiguous slice of allocated buffer elements,
    /// and dequeue the amount of elements returned by `f`.
    ///
    /// # Panics
    /// This function panics if the amount of elements returned by `f` is larger
    /// than the size of the slice passed into it.
    pub(crate) fn dequeue_many_with<'b, R, F>(&'b mut self, f: F) -> (usize, R)
    where
        F: FnOnce(&'b mut [u8]) -> (usize, R),
    {
        let capacity = self.capacity();
        let max_size = cmp::min(self.len(), capacity - self.read_at);
        let (size, result) = f(&mut self.storage[self.read_at..self.read_at + max_size]);
        assert!(size <= max_size);
        self.read_at = if capacity > 0 {
            (self.read_at + size) % capacity
        } else {
            0
        };
        self.length -= size;
        (size, result)
    }

    /// Dequeue as many elements from the buffer into the given slice as possible,
    /// and return the amount of elements that could fit.
    #[must_use]
    pub(crate) fn dequeue_slice(&mut self, data: &mut [u8]) -> usize {
        let (size_1, data) = self.dequeue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            data[..size].copy_from_slice(&buf[..size]);
            (size, &mut data[size..])
        });
        let (size_2, ()) = self.dequeue_many_with(|buf| {
            let size = cmp::min(buf.len(), data.len());
            data[..size].copy_from_slice(&buf[..size]);
            (size, ())
        });
        size_1 + size_2
    }
}

/// This is the "random access" ring buffer interface: it operates with element slices,
/// and allows to access elements of the buffer that are not adjacent to its head or tail.
impl<'a> RingBuffer<'a> {
    /// Return the largest contiguous slice of unallocated buffer elements starting
    /// at the given offset past the last allocated element, and up to the given size.
    #[must_use]
    pub(crate) fn get_unallocated(&mut self, offset: usize, mut size: usize) -> &mut [u8] {
        // We can't access past the end of unallocated data.
        if offset > self.window() {
            return &mut [];
        }
        // We can't enqueue more than there is free space.
        let start_at = self.get_idx(self.length + offset);
        let clamped_window = self.window() - offset;
        if size > clamped_window {
            size = clamped_window
        }
        // We can't contiguously enqueue past the end of the storage.
        let until_end = self.capacity() - start_at;
        if size > until_end {
            size = until_end
        }

        &mut self.storage[start_at..start_at + size]
    }

    /// Write as many elements from the given slice into unallocated buffer elements
    /// starting at the given offset past the last allocated element, and return
    /// the amount written.
    #[must_use]
    pub(crate) fn write_unallocated(&mut self, offset: usize, data: &[u8]) -> usize {
        let (size_1, offset, data) = {
            let slice = self.get_unallocated(offset, data.len());
            let slice_len = slice.len();
            slice.copy_from_slice(&data[..slice_len]);
            (slice_len, offset + slice_len, &data[slice_len..])
        };
        let size_2 = {
            let slice = self.get_unallocated(offset, data.len());
            let slice_len = slice.len();
            slice.copy_from_slice(&data[..slice_len]);
            slice_len
        };
        size_1 + size_2
    }

    /// Enqueue the given number of unallocated buffer elements.
    ///
    /// # Panics
    /// Panics if the number of elements given exceeds the number of unallocated elements.
    pub(crate) fn enqueue_unallocated(&mut self, count: usize) {
        assert!(count <= self.window());
        self.length += count;
    }

    /// Return the largest contiguous slice of allocated buffer elements starting
    /// at the given offset past the first allocated element, and up to the given size.
    #[must_use]
    pub(crate) fn get_allocated(&self, offset: usize, mut size: usize) -> &[u8] {
        // We can't read past the end of the allocated data.
        if offset > self.length {
            return &mut [];
        }
        // We can't read more than we have allocated.
        let start_at = self.get_idx(offset);
        let clamped_length = self.length - offset;
        if size > clamped_length {
            size = clamped_length
        }
        // We can't contiguously dequeue past the end of the storage.
        let until_end = self.capacity() - start_at;
        if size > until_end {
            size = until_end
        }

        &self.storage[start_at..start_at + size]
    }

    /// Dequeue the given number of allocated buffer elements.
    ///
    /// # Panics
    /// Panics if the number of elements given exceeds the number of allocated elements.
    pub(crate) fn dequeue_allocated(&mut self, count: usize) {
        assert!(count <= self.len());
        self.length -= count;
        self.read_at = self.get_idx(count);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_buffer_unallocated_offset_overflow() {
        let mut ring = RingBuffer::new(vec![0; 4]);
        assert_eq!(ring.enqueue_slice(b"ab"), 2);
        assert_eq!(ring.write_unallocated(usize::MAX, b"x"), 0);
        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"ab");
            (2, ())
        });
    }

    #[test]
    fn test_buffer_allocated_offset_overflow() {
        let mut ring = RingBuffer::new(vec![0; 4]);
        assert_eq!(ring.enqueue_slice(b"ab"), 2);
        let mut byte = [0; 1];
        assert_eq!(ring.dequeue_slice(&mut byte), 1);
        assert_eq!(&byte, b"a");
        assert_eq!(ring.get_allocated(usize::MAX, 1), b"");
        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"b");
            (1, ())
        });
    }

    #[test]
    fn test_buffer_length_changes() {
        let mut ring = RingBuffer::new(vec![0; 2]);
        assert!(ring.is_empty());
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 2);

        assert_eq!(ring.enqueue_slice(b"a"), 1);
        assert!(!ring.is_empty());
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 1);

        assert_eq!(ring.enqueue_slice(b"b"), 1);
        assert!(!ring.is_empty());
        assert_eq!(ring.len(), 2);
        assert_eq!(ring.capacity(), 2);
        assert_eq!(ring.window(), 0);
        assert_eq!(ring.enqueue_slice(b"c"), 0);
        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"ab");
            (2, ())
        });
        assert!(ring.is_empty());
        assert_eq!(ring.window(), 2);
    }

    #[test]
    fn test_buffer_enqueue_many_with() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(
            ring.enqueue_many_with(|buf| {
                assert_eq!(buf.len(), 12);
                buf[0..2].copy_from_slice(b"ab");
                (2, true)
            }),
            (2, true)
        );
        assert_eq!(ring.len(), 2);
        assert_eq!(&ring.storage[..], b"ab..........");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 2);
            buf[0..4].copy_from_slice(b"cdXX");
            (2, ())
        });
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"abcdXX......");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 4);
            buf[0..4].copy_from_slice(b"efgh");
            (4, ())
        });
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdefgh....");

        for _ in 0..4 {
            ring.dequeue_many_with(|buf| {
                buf[0] = b'.';
                (1, ())
            });
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"....efgh....");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 12 - 8);
            buf[0..4].copy_from_slice(b"ijkl");
            (4, ())
        });
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"....efghijkl");

        ring.enqueue_many_with(|buf| {
            assert_eq!(buf.len(), 4);
            buf[0..4].copy_from_slice(b"abcd");
            (4, ())
        });
        assert_eq!(ring.len(), 12);
        assert_eq!(&ring.storage[..], b"abcdefghijkl");

        for _ in 0..4 {
            ring.dequeue_many_with(|buf| {
                buf[0] = b'.';
                (1, ())
            });
        }
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcd....ijkl");
    }

    #[test]
    fn test_buffer_enqueue_slice() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefgh"), 8);
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdefgh....");

        for _ in 0..4 {
            ring.dequeue_many_with(|buf| {
                buf[0] = b'.';
                (1, ())
            });
        }
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"....efgh....");

        assert_eq!(ring.enqueue_slice(b"ijklabcd"), 8);
        assert_eq!(ring.len(), 12);
        assert_eq!(&ring.storage[..], b"abcdefghijkl");
    }

    #[test]
    fn test_buffer_dequeue_many_with() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        assert_eq!(
            ring.dequeue_many_with(|buf| {
                assert_eq!(buf.len(), 12);
                assert_eq!(buf, b"abcdefghijkl");
                buf[..4].copy_from_slice(b"....");
                (4, true)
            }),
            (4, true)
        );
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"....efghijkl");

        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"efghijkl");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        assert_eq!(ring.len(), 4);
        assert_eq!(&ring.storage[..], b"........ijkl");

        assert_eq!(ring.enqueue_slice(b"abcd"), 4);
        assert_eq!(ring.len(), 8);

        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"ijkl");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        ring.dequeue_many_with(|buf| {
            assert_eq!(buf, b"abcd");
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        assert_eq!(ring.len(), 0);
        assert_eq!(&ring.storage[..], b"............");
    }

    #[test]
    fn test_buffer_dequeue_slice() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        {
            let mut buf = [0; 8];
            assert_eq!(ring.dequeue_slice(&mut buf[..]), 8);
            assert_eq!(&buf[..], b"abcdefgh");
            assert_eq!(ring.len(), 4);
        }

        assert_eq!(ring.enqueue_slice(b"abcd"), 4);

        {
            let mut buf = [0; 8];
            assert_eq!(ring.dequeue_slice(&mut buf[..]), 8);
            assert_eq!(&buf[..], b"ijklabcd");
            assert_eq!(ring.len(), 0);
        }
    }

    #[test]
    fn test_buffer_get_unallocated() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.get_unallocated(16, 4), b"");

        {
            let buf = ring.get_unallocated(0, 4);
            buf.copy_from_slice(b"abcd");
        }
        assert_eq!(&ring.storage[..], b"abcd........");

        assert_eq!(ring.enqueue_many_with(|_| (4, ())).0, 4);
        assert_eq!(ring.len(), 4);

        {
            let buf = ring.get_unallocated(4, 8);
            buf.copy_from_slice(b"ijkl");
        }
        assert_eq!(&ring.storage[..], b"abcd....ijkl");

        assert_eq!(ring.enqueue_slice(b"EFGHIJKL"), 8);
        ring.dequeue_many_with(|buf| {
            buf[..4].copy_from_slice(b"abcd");
            (4, ())
        });
        assert_eq!(ring.len(), 8);
        assert_eq!(&ring.storage[..], b"abcdEFGHIJKL");

        {
            let buf = ring.get_unallocated(0, 8);
            buf.copy_from_slice(b"ABCD");
        }
        assert_eq!(&ring.storage[..], b"ABCDEFGHIJKL");
    }

    #[test]
    fn test_buffer_write_unallocated() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);
        assert_eq!(ring.enqueue_slice(b"abcdef"), 6);
        ring.dequeue_many_with(|buf| {
            buf[..6].copy_from_slice(b"ABCDEF");
            (6, ())
        });

        assert_eq!(ring.write_unallocated(0, b"ghi"), 3);
        assert_eq!(ring.get_unallocated(0, 3), b"ghi");

        assert_eq!(ring.write_unallocated(3, b"jklmno"), 6);
        assert_eq!(ring.get_unallocated(3, 3), b"jkl");

        assert_eq!(ring.write_unallocated(9, b"pqrstu"), 3);
        assert_eq!(ring.get_unallocated(9, 3), b"pqr");
    }

    #[test]
    fn test_buffer_get_allocated() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);

        assert_eq!(ring.get_allocated(16, 4), b"");
        assert_eq!(ring.get_allocated(0, 4), b"");

        let len_enqueued = ring.enqueue_slice(b"abcd");
        assert_eq!(ring.get_allocated(0, 8), b"abcd");
        assert_eq!(len_enqueued, 4);

        let len_enqueued = ring.enqueue_slice(b"efghijkl");
        ring.dequeue_many_with(|buf| {
            buf[..4].copy_from_slice(b"....");
            (4, ())
        });
        assert_eq!(ring.get_allocated(4, 8), b"ijkl");
        assert_eq!(len_enqueued, 8);

        let len_enqueued = ring.enqueue_slice(b"abcd");
        assert_eq!(ring.get_allocated(4, 8), b"ijkl");
        assert_eq!(len_enqueued, 4);
    }

    #[test]
    fn test_buffer_get_allocated_wrap() {
        let mut ring = RingBuffer::new(vec![b'.'; 12]);
        assert_eq!(ring.enqueue_slice(b"abcdefghijkl"), 12);

        let data = ring.get_allocated(0, 6);
        assert_eq!(data.len(), 6);
        assert_eq!(data, b"abcdef");

        ring.dequeue_many_with(|buf| {
            buf[..6].copy_from_slice(b"ABCDEF");
            (6, ())
        });
        assert_eq!(ring.enqueue_slice(b"mno"), 3);

        assert_eq!(ring.get_allocated(3, 6), b"jkl");
        assert_eq!(ring.get_allocated(6, 3), b"mno");

        let mut data = [0; 6];
        let tail = ring.get_allocated(6, 6);
        assert_eq!(tail.len(), 3);
        data[..tail.len()].copy_from_slice(tail);
        assert_eq!(&data, b"mno\x00\x00\x00");
    }

    #[test]
    fn test_buffer_with_no_capacity() {
        let mut no_capacity: RingBuffer = RingBuffer::new(vec![]);

        // Call all functions that calculate the remainder against rx_buffer.capacity()
        // with a backing storage with a length of 0.
        assert_eq!(no_capacity.get_unallocated(0, 0), &[]);
        assert_eq!(no_capacity.get_allocated(0, 0), &[]);
        no_capacity.dequeue_allocated(0);
        assert_eq!(
            no_capacity.enqueue_many_with(|buf| {
                assert_eq!(buf, &[]);
                (0, ())
            }),
            (0, ())
        );
        assert_eq!(no_capacity.contiguous_window(), 0);
    }

    /// Use the buffer a bit. Then empty it and put in an item of
    /// maximum size. By detecting a length of 0, the implementation
    /// can reset the current buffer position.
    #[test]
    fn test_buffer_write_wholly() {
        let mut ring = RingBuffer::new(vec![b'.'; 8]);
        assert_eq!(ring.enqueue_slice(b"ab"), 2);
        assert_eq!(ring.enqueue_slice(b"cd"), 2);
        assert_eq!(ring.len(), 4);
        let mut bytes = [0; 4];
        assert_eq!(ring.dequeue_slice(&mut bytes), 4);
        assert_eq!(&bytes, b"abcd");
        assert_eq!(ring.len(), 0);

        assert_eq!(
            ring.enqueue_many_with(|buf| {
                assert_eq!(buf.len(), 8);
                (8, ())
            }),
            (8, ())
        );
    }
}
