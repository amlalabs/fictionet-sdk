//! The length-prefixed Ethernet stream that QEMU's `-netdev stream`,
//! libkrun's Unix stream backend and passt use: each frame is a 32-bit
//! big-endian length, then that many bytes, with no FCS and no virtio-net
//! header.
//!
//! [`Decoder`] splits what is read into frames, and [`Outbox`] holds what
//! is to be written, so a frame can go out in pieces. Neither does I/O.

/// The longest frame the decoder takes: QEMU's stream backend buffers 68
/// KiB, the most any of these backends sends. A longer length means the
/// stream is broken.
pub const MAX_STREAM_FRAME: usize = 69_632;

/// Splits a stream into frames. It holds a few whole frames, so one read
/// can take several.
pub struct Decoder {
    buf: Vec<u8>,
    start: usize,
    end: usize,
}

/// A length prefix longer than [`MAX_STREAM_FRAME`].
#[derive(Debug, PartialEq, Eq)]
pub struct TooLong(
    /// The length the prefix gave.
    pub usize,
);

impl Default for Decoder {
    fn default() -> Decoder {
        Decoder::new()
    }
}

impl Decoder {
    /// An empty decoder.
    pub fn new() -> Decoder {
        Decoder {
            buf: vec![0; 4 * (4 + MAX_STREAM_FRAME)],
            start: 0,
            end: 0,
        }
    }

    /// Where the next read should go. Never empty.
    pub fn spare(&mut self) -> &mut [u8] {
        if self.start == self.end {
            self.start = 0;
            self.end = 0;
        } else if self.buf.len() - self.end < 4 + MAX_STREAM_FRAME {
            // Move the partial frame to the front, so a whole frame fits.
            self.buf.copy_within(self.start..self.end, 0);
            self.end -= self.start;
            self.start = 0;
        }
        &mut self.buf[self.end..]
    }

    /// Records that `n` bytes were read into [`spare`](Decoder::spare).
    pub fn filled(&mut self, n: usize) {
        self.end += n;
    }

    /// The next whole frame, if one has arrived.
    pub fn next_frame(&mut self) -> Result<Option<&[u8]>, TooLong> {
        let have = &self.buf[self.start..self.end];
        if have.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([have[0], have[1], have[2], have[3]]) as usize;
        if len > MAX_STREAM_FRAME {
            return Err(TooLong(len));
        }
        if have.len() < 4 + len {
            return Ok(None);
        }
        let at = self.start + 4;
        self.start = at + len;
        Ok(Some(&self.buf[at..at + len]))
    }
}

/// Frames waiting to be written to the stream, each with its length
/// prefix. It holds at most `cap` bytes; a frame that does not fit is
/// dropped, as a full network card queue drops it.
pub struct Outbox {
    buf: Vec<u8>,
    start: usize,
    cap: usize,
}

impl Outbox {
    /// An empty outbox that holds at most `cap` bytes.
    pub fn new(cap: usize) -> Outbox {
        Outbox {
            buf: Vec::new(),
            start: 0,
            cap,
        }
    }

    /// Queues one frame made of `parts`. `false` if it was dropped.
    pub fn push(&mut self, parts: &[&[u8]]) -> bool {
        let len: usize = parts.iter().map(|p| p.len()).sum();
        if self.len() + 4 + len > self.cap {
            return false;
        }
        if self.start > 0 && self.start >= self.buf.len() / 2 {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(&(len as u32).to_be_bytes());
        for p in parts {
            self.buf.extend_from_slice(p);
        }
        true
    }

    /// The bytes waiting.
    pub fn len(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Whether nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes to write next.
    pub fn pending(&self) -> &[u8] {
        &self.buf[self.start..]
    }

    /// Records that `n` bytes of [`pending`](Outbox::pending) were written.
    pub fn written(&mut self, n: usize) {
        self.start += n;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(frames: &[&[u8]]) -> Vec<u8> {
        let mut s = Vec::new();
        for f in frames {
            s.extend_from_slice(&(f.len() as u32).to_be_bytes());
            s.extend_from_slice(f);
        }
        s
    }

    fn feed(d: &mut Decoder, bytes: &[u8]) {
        let spare = d.spare();
        spare[..bytes.len()].copy_from_slice(bytes);
        d.filled(bytes.len());
    }

    #[test]
    fn decoder_splits_frames_across_reads() {
        let big = vec![7u8; 9014];
        let s = stream(&[b"first", &big, b"", b"last"]);
        let mut d = Decoder::new();
        let mut got: Vec<Vec<u8>> = Vec::new();
        // One byte at a time, then in odd pieces.
        for b in &s {
            feed(&mut d, std::slice::from_ref(b));
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f.to_vec());
            }
        }
        assert_eq!(
            got,
            vec![b"first".to_vec(), big.clone(), vec![], b"last".to_vec()]
        );
        got.clear();
        for piece in s.chunks(1000) {
            feed(&mut d, piece);
            while let Some(f) = d.next_frame().unwrap() {
                got.push(f.to_vec());
            }
        }
        assert_eq!(got.len(), 4);
        assert_eq!(got[1], big);
    }

    #[test]
    fn decoder_keeps_room_for_a_whole_frame() {
        // Many full-size frames, read in pieces that leave a partial frame
        // at the end of the buffer each time.
        let f = vec![1u8; MAX_STREAM_FRAME];
        let s = stream(&[&f, &f, &f, &f, &f, &f, &f]);
        let mut d = Decoder::new();
        let mut n = 0;
        let mut at = 0;
        while at < s.len() {
            let spare = d.spare();
            assert!(spare.len() >= 4 + MAX_STREAM_FRAME);
            let k = spare.len().min(s.len() - at).min(100_000);
            spare[..k].copy_from_slice(&s[at..at + k]);
            d.filled(k);
            at += k;
            while let Some(frame) = d.next_frame().unwrap() {
                assert_eq!(frame.len(), MAX_STREAM_FRAME);
                n += 1;
            }
        }
        assert_eq!(n, 7);
    }

    #[test]
    fn decoder_refuses_a_length_past_qemus_buffer() {
        let mut d = Decoder::new();
        feed(&mut d, &((MAX_STREAM_FRAME + 1) as u32).to_be_bytes());
        assert_eq!(d.next_frame(), Err(TooLong(MAX_STREAM_FRAME + 1)));
        let mut d = Decoder::new();
        feed(&mut d, &u32::MAX.to_be_bytes());
        assert!(d.next_frame().is_err());
    }

    #[test]
    fn outbox_frames_and_drops_when_full() {
        let mut o = Outbox::new(20);
        assert!(o.push(&[b"abc", b"de"]));
        assert_eq!(o.pending(), &[0, 0, 0, 5, b'a', b'b', b'c', b'd', b'e']);
        assert!(!o.push(&[&[0u8; 8]]), "9 + 12 > 20");
        assert!(o.push(&[&[9u8; 7]]));
        assert_eq!(o.len(), 20);
        o.written(9);
        assert_eq!(o.pending(), &[0, 0, 0, 7, 9, 9, 9, 9, 9, 9, 9]);
        assert!(o.push(&[b"x"]), "room again after a write");
        o.written(o.len());
        assert!(o.is_empty());
    }
}
