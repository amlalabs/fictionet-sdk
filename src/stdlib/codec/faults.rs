extern crate alloc;

use alloc::vec::Vec;
use core::{convert::Infallible, time::Duration};
use fictionet::stdlib::codec::{Interceptor, Lcg, Rewrite, RewriteError};

/// When a rule applies. Call numbers start at one in each fault domain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Trigger {
    /// Every call that reaches this rule.
    Always,
    /// Exactly this call number. Zero never matches.
    At(u64),
    /// Every nth call. Zero never matches.
    Every(u64),
    /// Draw below `out_of` and match when below `take`.
    /// Zero `out_of` never matches; `take >= out_of` always matches.
    /// Other draws use the LCG's 31-bit modulo reduction, not an exact
    /// uniform distribution for every denominator.
    Chance {
        /// Number of matching outcomes.
        take: u32,
        /// Number of possible outcomes.
        out_of: u32,
    },
}

/// A rule in an ordered plan. Only the first matching rule is applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule<F> {
    /// Selection condition.
    pub when: Trigger,
    /// Action when this rule matches.
    pub fault: F,
}

/// An edit to a caller-defined byte chunk before it is pushed to a stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ByteFault {
    /// Request a delay before these unchanged bytes.
    Delay(Duration),
    /// Discard the entire chunk.
    Drop,
    /// Emit this many exact copies, including the original. Zero drops it.
    Duplicate(usize),
    /// Retain at most this many bytes from the beginning of the chunk.
    Truncate(usize),
    /// XOR one byte. Empty input and an out-of-range fixed offset are inert.
    Corrupt {
        /// Byte index, or `None` to draw an index from the seeded LCG.
        offset: Option<usize>,
        /// Bits to flip. Zero leaves the byte unchanged.
        xor: u8,
    },
    /// Substitute these exact bytes without protocol validation.
    Replace(Vec<u8>),
}

/// A policy action for a decoded item, applied through an interceptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ItemFault<T> {
    /// Request a delay before forwarding the original bytes.
    Delay(Duration),
    /// Discard the item.
    Drop,
    /// Forward this many copies of its raw bytes, including the original.
    Duplicate(usize),
    /// Substitute values for the interceptor's writer.
    Replace(Vec<T>),
}

/// One item decision plus an optional delay to perform before its output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FaultAction<T> {
    /// A marker for the world. This code never sleeps or reads a clock.
    pub delay: Option<Duration>,
    /// The decision to pass to [`Interceptor::apply`] or `apply_with`.
    pub rewrite: Rewrite<T>,
}

/// Deterministic byte and item fault plans with an explicit seed.
///
/// Plans are borrowed per call and remain owned and bounded by world code.
/// Byte and item calls have independent counters and share one LCG. The
/// same seed, plans, and call sequence give the same decisions and bytes.
/// Counters stop matching after `u64::MAX` calls instead of wrapping.
/// Rules are checked in order, so randomness is drawn only for rules that
/// are reached and for selected random corruption offsets.
///
/// Byte rules apply to each supplied chunk before [`Stream::push`](fictionet::stdlib::codec::Stream::push).
/// Chunk boundaries are part of that input; changing them can change byte
/// faults. Item rules run once per decoded item, independent of push sizes.
/// Delays are returned markers. Honor each marker before sending or pushing
/// the bytes from that call, including when collecting several outputs.
///
/// ```
/// use fictionet::stdlib::{codec::{Faults, ItemFault, Rule, Trigger, Interceptor}, modbus};
/// let mut faults = Faults::new(7, 1024);
/// let plan = [Rule { when: Trigger::At(1), fault: ItemFault::<modbus::Frame>::Duplicate(2) }];
/// let raw = [0, 1, 0, 0, 0, 2, 1, 3];
/// let action = faults.item(&plan);
/// let mut output = Vec::new();
/// Interceptor::new(1024).apply(&raw, action.rewrite, &mut output)?;
/// assert_eq!(output, raw.repeat(2));
/// # Ok::<(), Box<dyn core::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct Faults {
    rng: Lcg,
    byte_at: Option<u64>,
    item_at: Option<u64>,
    output: Interceptor,
}
impl Faults {
    /// Starts both counters at one. `max_output` bounds the total length
    /// of each byte output vector, clamped as in [`Interceptor::new`].
    /// Item output is bounded by the interceptor that applies the decision.
    pub fn new(seed: u64, max_output: usize) -> Self {
        Self {
            rng: Lcg::new(seed),
            byte_at: Some(1),
            item_at: Some(1),
            output: Interceptor::new(max_output),
        }
    }

    /// Edits one input chunk before a stream sees it. Returns a delay marker
    /// for the appended bytes. An error leaves `out` unchanged but advances
    /// the plan counter and any random draws. Retrying is a new plan call.
    /// No match copies the chunk unchanged. Scratch bytes and destination
    /// length are each bounded by the configured output limit.
    pub fn bytes(
        &mut self,
        plan: &[Rule<ByteFault>],
        input: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Option<Duration>, RewriteError<Infallible>> {
        let call = self.byte_at;
        self.byte_at = call.and_then(|n| n.checked_add(1));
        let fault = plan
            .iter()
            .find(|rule| self.matches(rule.when, call))
            .map(|rule| &rule.fault);
        let mut delay = None;
        let rewrite = match fault {
            None => Rewrite::Forward,
            Some(ByteFault::Delay(duration)) => {
                delay = Some(*duration);
                Rewrite::Forward
            }
            Some(ByteFault::Drop) => Rewrite::Drop,
            Some(ByteFault::Duplicate(copies)) => Rewrite::Repeat(*copies),
            Some(ByteFault::Truncate(len)) => {
                Rewrite::Raw(self.copy(input.get(..*len).unwrap_or(input))?)
            }
            Some(ByteFault::Replace(bytes)) => Rewrite::Raw(self.copy(bytes)?),
            Some(ByteFault::Corrupt { offset, xor }) => {
                let mut bytes = self.copy(input)?;
                let at = offset.unwrap_or_else(|| self.rng.index(bytes.len()));
                if let Some(byte) = bytes.get_mut(at) {
                    *byte ^= xor;
                }
                Rewrite::Raw(bytes)
            }
        };
        self.output
            .apply_with(input, rewrite, out, |never: &Infallible, _| match *never {})?;
        Ok(delay)
    }

    /// Selects one item's interceptor policy. Replacement values are cloned
    /// from the first matching rule. Their count and size are bounded by the
    /// world-owned plan and each value's writer limits. No matching rule
    /// yields Forward. This method neither encodes nor retains any item.
    pub fn item<T: Clone>(&mut self, plan: &[Rule<ItemFault<T>>]) -> FaultAction<T> {
        let call = self.item_at;
        self.item_at = call.and_then(|n| n.checked_add(1));
        let fault = plan
            .iter()
            .find(|rule| self.matches(rule.when, call))
            .map(|rule| &rule.fault);
        let mut delay = None;
        let rewrite = match fault {
            None => Rewrite::Forward,
            Some(ItemFault::Delay(duration)) => {
                delay = Some(*duration);
                Rewrite::Forward
            }
            Some(ItemFault::Drop) => Rewrite::Drop,
            Some(ItemFault::Duplicate(copies)) => Rewrite::Repeat(*copies),
            Some(ItemFault::Replace(items)) => Rewrite::Replace(items.clone()),
        };
        FaultAction { delay, rewrite }
    }

    fn matches(&mut self, trigger: Trigger, call: Option<u64>) -> bool {
        let Some(call) = call else { return false };
        match trigger {
            Trigger::Always => true,
            Trigger::At(n) => n != 0 && call == n,
            Trigger::Every(n) => n != 0 && call.is_multiple_of(n),
            Trigger::Chance { take, out_of } => {
                out_of != 0
                    && (take >= out_of || self.rng.below(u64::from(out_of)) < u64::from(take))
            }
        }
    }

    fn copy(&self, bytes: &[u8]) -> Result<Vec<u8>, RewriteError<Infallible>> {
        if bytes.len() > self.output.limit() {
            return Err(RewriteError::TooLong {
                limit: self.output.limit(),
            });
        }
        let mut out = Vec::new();
        out.try_reserve_exact(bytes.len())
            .map_err(|_| RewriteError::Allocation)?;
        out.extend_from_slice(bytes);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_byte_faults_and_delay_markers() {
        let mut faults = Faults::new(7, 16);
        let cases = [
            (
                ByteFault::Delay(Duration::from_millis(3)),
                b"abc".as_slice(),
            ),
            (ByteFault::Drop, b""),
            (ByteFault::Duplicate(2), b"abcabc"),
            (ByteFault::Truncate(2), b"ab"),
            (
                ByteFault::Corrupt {
                    offset: Some(1),
                    xor: 1,
                },
                b"acc",
            ),
            (ByteFault::Replace(b"z".to_vec()), b"z"),
        ];
        for (fault, expected) in cases {
            let expected_delay = if let ByteFault::Delay(d) = fault {
                Some(d)
            } else {
                None
            };
            let mut out = b"!".to_vec();
            let marker = faults
                .bytes(
                    &[Rule {
                        when: Trigger::Always,
                        fault,
                    }],
                    b"abc",
                    &mut out,
                )
                .unwrap();
            assert_eq!(marker, expected_delay);
            assert_eq!(&out[1..], expected);
        }
    }

    #[test]
    fn repeatable_draws_and_plan_order() {
        let plan = [
            Rule {
                when: Trigger::Chance { take: 1, out_of: 3 },
                fault: ByteFault::Drop,
            },
            Rule {
                when: Trigger::Always,
                fault: ByteFault::Corrupt {
                    offset: None,
                    xor: 0x80,
                },
            },
        ];
        let run = |seed| {
            let mut faults = Faults::new(seed, 4096);
            let mut out = Vec::new();
            for _ in 0..100 {
                faults.bytes(&plan, b"abcdef", &mut out).unwrap();
            }
            out
        };
        assert_eq!(run(27), run(27));
        assert_ne!(run(27), run(28));
        let mut faults = Faults::new(0, 8);
        let rules = [
            Rule {
                when: Trigger::At(1),
                fault: ItemFault::<u8>::Drop,
            },
            Rule {
                when: Trigger::Every(2),
                fault: ItemFault::Duplicate(2),
            },
        ];
        assert_eq!(faults.item(&rules).rewrite, Rewrite::Drop);
        assert_eq!(faults.item(&rules).rewrite, Rewrite::Repeat(2));
        assert_eq!(faults.item(&rules).rewrite, Rewrite::Forward);
    }

    #[test]
    fn byte_bounds_empty_input_and_counter_exhaustion() {
        let mut faults = Faults::new(1, 3);
        let mut out = vec![42];
        let plan = [Rule {
            when: Trigger::Always,
            fault: ByteFault::Duplicate(usize::MAX),
        }];
        assert!(faults.bytes(&plan, b"abc", &mut out).is_err());
        assert_eq!(out, [42]);
        faults.bytes(&plan, b"", &mut out).unwrap();
        assert!(!faults.matches(Trigger::Every(0), Some(1)));
        assert!(!faults.matches(
            Trigger::Chance {
                take: u32::MAX,
                out_of: 0
            },
            Some(1)
        ));
        faults.item_at = Some(u64::MAX);
        let plan = [Rule {
            when: Trigger::Always,
            fault: ItemFault::<u8>::Drop,
        }];
        assert_eq!(faults.item(&plan).rewrite, Rewrite::Drop);
        assert_eq!(faults.item(&plan).rewrite, Rewrite::Forward);
    }
}
