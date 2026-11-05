use super::alloc::vec::Vec;
use fictionet::stdlib::codec::{Decode, Fail, Stream};

/// Feeds the supplied chunks through a real stream, then ends it once.
/// Returns delivered items and the terminal failure. A stuck decoder panics.
/// The caller chooses chunk boundaries and asserts protocol results, including
/// errors for incomplete input. No prefixes or alternative chunkings are run.
///
/// Calls `inspect` initially, after each push and each `next` (including `None`),
/// so tests can assert protocol-specific storage bounds. Internal skips and
/// progress are handled by [`Stream`]. The stream remains available to check
/// its consumed offset or hand off bytes following an early end.
///
/// ```
/// use fictionet::stdlib::{codec::{Frames, Stream}, protocols::tpkt::Packet,
///     test_support::{chunks, decode_chunks}};
/// let bytes = [3, 0, 0, 7, 1, 2, 3];
/// let mut stream = Stream::new(Frames::<Packet>::new());
/// let (items, failure) = decode_chunks(&mut stream, chunks(&bytes, &[1, 3]), |s| {
///     assert_eq!(s.held(), 0);
///     assert!(s.allocated() <= 2 * 65535);
/// });
/// assert_eq!(items, [Packet::new(vec![1, 2, 3])]);
/// assert_eq!(failure, None);
/// assert_eq!(stream.offset(), bytes.len() as u64);
/// ```
pub fn decode_chunks<'a, D: Decode>(
    stream: &mut Stream<D>,
    input: impl IntoIterator<Item = &'a [u8]>,
    mut inspect: impl FnMut(&Stream<D>),
) -> (Vec<D::Item>, Option<Fail<D::Error>>)
where
    D::Error: Clone,
{
    let mut items = Vec::new();
    inspect(stream);
    for mut chunk in input {
        while !chunk.is_empty() && !stream.is_done() {
            let used = stream.push(chunk);
            inspect(stream);
            chunk = &chunk[used..];
            let before = stream.offset();
            loop {
                let next = stream.next();
                inspect(stream);
                match next {
                    Some(Ok(item)) => items.push(item),
                    Some(Err(error)) => {
                        assert!(
                            !matches!(error, Fail::Stuck { .. }),
                            "decoder made no progress"
                        );
                        return (items, Some(error));
                    }
                    None => break,
                }
            }
            assert!(
                used > 0 || stream.offset() > before || stream.is_done(),
                "input made no progress"
            );
        }
        if stream.is_done() {
            break;
        }
    }
    stream.end();
    loop {
        let next = stream.next();
        inspect(stream);
        match next {
            Some(Ok(item)) => items.push(item),
            Some(Err(error)) => {
                assert!(
                    !matches!(error, Fail::Stuck { .. }),
                    "decoder made no progress"
                );
                return (items, Some(error));
            }
            None => return (items, None),
        }
    }
}
