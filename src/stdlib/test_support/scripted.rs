use fictionet::stdlib::codec::{Decode, Step};

/// A test decoder with caller state and explicit decision hooks.
///
/// `before_call` runs before every call to the inner decoder, including calls
/// with empty input or EOF. `after_item` runs only after an item, before it is
/// returned to the driver. It may map the item to include caller observations.
/// To defer a decision until the next call, record it in the caller state.
///
/// The hooks must preserve the [`Decode`] progress contract. In particular,
/// repeated `Need` calls must not change later results. Capacity, held bytes,
/// the decoder name, errors, step variants and consumed counts are forwarded.
///
/// ```
/// use fictionet::stdlib::{
///     codec::{Ending, Lines},
///     test_support::{Scripted, decode_all},
/// };
/// let make = || Scripted::new(
///     Lines::new(32, Ending::Crlf),
///     0usize,
///     |_, _| {},
///     |_, count, item| {
///         *count += 1;
///         (item, *count)
///     },
/// );
/// let (items, failure) = decode_all(make, b"one\r\ntwo\r\n");
/// assert_eq!(failure, None);
/// assert_eq!(items.iter().map(|(_, count)| *count).collect::<Vec<_>>(), [1, 2]);
/// ```
pub struct Scripted<D, S, B, A> {
    decoder: D,
    state: S,
    before_call: B,
    after_item: A,
}

impl<D, S, B, A, T> Scripted<D, S, B, A>
where
    D: Decode,
    B: FnMut(&mut D, &mut S),
    A: FnMut(&mut D, &mut S, D::Item) -> T,
{
    /// Wraps `decoder` with caller `state` and the two decision hooks.
    pub fn new(decoder: D, state: S, before_call: B, after_item: A) -> Self {
        Self {
            decoder,
            state,
            before_call,
            after_item,
        }
    }
}

impl<D, S, B, A, T> Decode for Scripted<D, S, B, A>
where
    D: Decode,
    B: FnMut(&mut D, &mut S),
    A: FnMut(&mut D, &mut S, D::Item) -> T,
{
    type Item = T;
    type Error = D::Error;
    const NAME: &'static str = D::NAME;

    fn capacity(&self) -> usize {
        self.decoder.capacity()
    }

    fn held(&self) -> usize {
        self.decoder.held()
    }

    fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<T>, D::Error> {
        (self.before_call)(&mut self.decoder, &mut self.state);
        let step = self.decoder.decode(bytes, eof)?;
        Ok(step.map(|item| (self.after_item)(&mut self.decoder, &mut self.state, item)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::{
        codec::{Ending, Lines},
        test_support::contract,
    };

    struct Probe {
        step: Option<Result<Step<u8>, std::io::Error>>,
        ready: bool,
        decoded: bool,
    }

    impl Decode for Probe {
        type Item = u8;
        type Error = std::io::Error;
        const NAME: &'static str = "probe";

        fn capacity(&self) -> usize {
            7 + usize::from(self.ready)
        }

        fn held(&self) -> usize {
            2 + usize::from(self.decoded)
        }

        fn decode(&mut self, bytes: &[u8], eof: bool) -> Result<Step<u8>, Self::Error> {
            assert!(self.ready);
            assert_eq!(bytes, b"abc");
            assert!(eof);
            self.decoded = true;
            self.step.take().unwrap()
        }
    }

    #[test]
    fn forwards_steps_errors_and_metadata_in_hook_order() {
        for (step, expected) in [
            (Ok(Step::Item(9, 3)), Ok(Step::Item((9, 1), 3))),
            (Ok(Step::Item(9, 0)), Ok(Step::Item((9, 1), 0))),
            (Ok(Step::Skip(2)), Ok(Step::Skip(2))),
            (Ok(Step::Skip(0)), Ok(Step::Skip(0))),
            (Ok(Step::Need), Ok(Step::Need)),
            (Ok(Step::End), Ok(Step::End)),
            (
                Err(std::io::Error::other("probe fault")),
                Err("probe fault".to_owned()),
            ),
        ] {
            let mut before_calls = 0;
            let mut after_calls = 0;
            let mut decoder = Scripted::new(
                Probe {
                    step: Some(step),
                    ready: false,
                    decoded: false,
                },
                0,
                |decoder, state| {
                    assert!(!decoder.decoded);
                    decoder.ready = true;
                    *state += 1;
                    before_calls += 1;
                },
                |decoder, state, item| {
                    assert!(decoder.decoded);
                    after_calls += 1;
                    (item, *state)
                },
            );
            fn name<D: Decode>(_: &D) -> &'static str {
                D::NAME
            }
            assert_eq!(name(&decoder), Probe::NAME);
            assert_eq!(decoder.capacity(), 7);
            assert_eq!(decoder.held(), 2);
            let actual = decoder
                .decode(b"abc", true)
                .map_err(|error| error.to_string());
            assert_eq!(actual, expected);
            assert_eq!(decoder.capacity(), 8);
            assert_eq!(decoder.held(), 3);
            assert_eq!(before_calls, 1);
            assert_eq!(
                after_calls,
                usize::from(matches!(expected, Ok(Step::Item(..))))
            );
        }
    }

    #[test]
    fn deferred_decisions_preserve_chunking_and_progress() {
        let make = || {
            Scripted::new(
                Lines::new(32, Ending::Crlf),
                (false, 0usize),
                |_, (pending, count)| {
                    if core::mem::take(pending) {
                        *count += 1;
                    }
                },
                |_, (pending, count), item| {
                    assert!(!*pending);
                    *pending = true;
                    (item, *count)
                },
            )
        };
        let (items, failure) = contract::check_decode(make, b"one\r\ntwo\r\n");
        assert_eq!(failure, None);
        assert_eq!(items, [(Ok(b"one".to_vec()), 0), (Ok(b"two".to_vec()), 1)]);
    }
}
