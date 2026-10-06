use super::{Buffer, Decode, Step, Wire, alloc::vec::Vec};
use core::{convert::Infallible, error::Error, fmt, marker::PhantomData};

/// Applies a closure to each item without changing framing or errors.
pub struct Map<D, F> {
    inner: D,
    f: F,
}
impl<D, F> Map<D, F> {
    /// Wraps a decoder and its item mapping closure.
    pub fn new(inner: D, f: F) -> Self {
        Self { inner, f }
    }
    /// Access to the wrapped decoder for mode changes between items.
    pub fn inner(&mut self) -> &mut D {
        &mut self.inner
    }
}
impl<D: Decode, U, F: FnMut(D::Item) -> U> Decode for Map<D, F> {
    type Item = U;
    type Error = D::Error;
    const NAME: &'static str = D::NAME;
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
    fn held(&self) -> usize {
        self.inner.held()
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<U>, D::Error> {
        Ok(match self.inner.decode(input, eof)? {
            Step::Item(item, n) => Step::Item((self.f)(item), n),
            Step::Skip(n) => Step::Skip(n),
            Step::Need => Step::Need,
            Step::End => Step::End,
        })
    }
}

/// Collects one complete [`Wire`] value at EOF, including empty values.
/// Input stays in the driver's buffer.
pub struct Collect<M> {
    limit: usize,
    taken: bool,
    marker: PhantomData<M>,
}
impl<M> Collect<M> {
    /// Accepts at most `limit` bytes. Clamps to [`Buffer::MAX_LIMIT`] minus
    /// one so a byte beyond the limit can be refused before EOF.
    pub fn new(limit: usize) -> Self {
        Self {
            limit: limit.min(Buffer::MAX_LIMIT.saturating_sub(1)),
            taken: false,
            marker: PhantomData,
        }
    }
}
/// Why collection failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CollectError<E> {
    /// The input exceeded the configured limit.
    TooLong {
        /// Maximum accepted bytes.
        limit: usize,
    },
    /// The complete bytes failed to parse.
    Parse(E),
}
impl<E: fmt::Display> fmt::Display for CollectError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { limit } => write!(f, "collection exceeds {limit} bytes"),
            Self::Parse(e) => write!(f, "collection parse: {e}"),
        }
    }
}
impl<E: Error> Error for CollectError<E> {}
impl<M: Wire> Decode for Collect<M> {
    type Item = M;
    type Error = CollectError<M::ParseError>;
    const NAME: &'static str = "collection";
    fn capacity(&self) -> usize {
        self.limit.saturating_add(1)
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<M>, Self::Error> {
        if self.taken {
            return Ok(Step::End);
        }
        if input.len() > self.limit {
            return Err(CollectError::TooLong { limit: self.limit });
        }
        if !eof {
            return Ok(Step::Need);
        }
        let item = M::parse(input).map_err(CollectError::Parse)?;
        self.taken = true;
        Ok(Step::Item(item, input.len()))
    }
}

/// Accepted line terminators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ending {
    /// Only CR followed by LF.
    Crlf,
    /// LF, optionally preceded by CR.
    LfOrCrlf,
    /// LF, CR, or CR followed by LF. A final CR waits for one more byte
    /// or EOF so a split CRLF remains one terminator.
    LfOrCrOrCrlf,
}
/// Why one line was refused. Framing continues after the refused line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LineError {
    /// The content, excluding its terminator, was too long.
    TooLong {
        /// Maximum content bytes.
        max: usize,
    },
    /// A bare LF was used when CRLF was required.
    BareLf,
    /// EOF arrived before the line terminator.
    Unterminated,
}
impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong { max } => write!(f, "line exceeds {max} bytes"),
            Self::BareLf => f.write_str("line requires CRLF"),
            Self::Unterminated => f.write_str("unterminated line"),
        }
    }
}
impl Error for LineError {}

/// Incremental line framing with a content limit and an ending policy.
/// Overlong lines produce one error item, then skip through their terminator.
/// The scan cursor keeps work linear, including split terminators.
pub struct Lines {
    max: usize,
    ending: Ending,
    scanned: usize,
    skipping: bool,
}
impl Lines {
    /// Creates a reader. `max` excludes the terminator and is clamped to
    /// [`Buffer::MAX_LIMIT`] minus two. Capacity includes both CR and LF.
    pub fn new(max: usize, ending: Ending) -> Self {
        Self {
            max: max.min(Buffer::MAX_LIMIT.saturating_sub(2)),
            ending,
            scanned: 0,
            skipping: false,
        }
    }
}
impl Decode for Lines {
    type Item = Result<Vec<u8>, LineError>;
    type Error = Infallible;
    const NAME: &'static str = "lines";
    fn capacity(&self) -> usize {
        self.max.saturating_add(2)
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Infallible> {
        if self.skipping {
            self.scanned = 0;
            if let Some(i) = input.iter().position(|b| {
                *b == b'\n' || (self.ending == Ending::LfOrCrOrCrlf && *b == b'\r')
            }) {
                let mut n = i.saturating_add(1);
                if self.ending == Ending::LfOrCrOrCrlf && input.get(i) == Some(&b'\r') {
                    if n == input.len() && !eof {
                        return Ok(if i == 0 { Step::Need } else { Step::Skip(i) });
                    }
                    if input.get(n) == Some(&b'\n') {
                        n = n.saturating_add(1);
                    }
                }
                self.skipping = false;
                return Ok(Step::Skip(n));
            }
            return Ok(if input.is_empty() {
                Step::Need
            } else {
                Step::Skip(input.len())
            });
        }
        let scan = self.scanned.min(input.len());
        // Stop at capacity even if the caller supplied a larger buffer.
        // This keeps the TooLong decision independent of chunk boundaries.
        let stop = input.len().min(self.capacity());
        let newline = input
            .get(scan..stop)
            .unwrap_or_default()
            .iter()
            .position(|b| {
                *b == b'\n' || (self.ending == Ending::LfOrCrOrCrlf && *b == b'\r')
            })
            .map(|i| scan.saturating_add(i));
        if let Some(i) = newline {
            let any_cr = self.ending == Ending::LfOrCrOrCrlf;
            let mut n = i.saturating_add(1);
            if any_cr && input.get(i) == Some(&b'\r') {
                if n == input.len() && !eof {
                    self.scanned = i;
                    if i <= self.max {
                        return Ok(Step::Need);
                    }
                    self.scanned = 0;
                    self.skipping = true;
                    return Ok(Step::Item(Err(LineError::TooLong { max: self.max }), i));
                }
                if input.get(n) == Some(&b'\n') {
                    n = n.saturating_add(1);
                }
            }
            let cr = !any_cr && i.checked_sub(1).and_then(|p| input.get(p)) == Some(&b'\r');
            let content = i.saturating_sub(usize::from(cr));
            self.scanned = 0;
            let line = if content > self.max {
                Err(LineError::TooLong { max: self.max })
            } else if !cr && self.ending == Ending::Crlf {
                Err(LineError::BareLf)
            } else {
                Ok(input.get(..content).unwrap_or_default().to_vec())
            };
            return Ok(Step::Item(line, n));
        }
        self.scanned = stop;
        if stop >= self.capacity() {
            self.scanned = 0;
            self.skipping = true;
            return Ok(Step::Item(Err(LineError::TooLong { max: self.max }), stop));
        }
        if eof && !input.is_empty() {
            self.scanned = 0;
            return Ok(Step::Item(Err(LineError::Unterminated), input.len()));
        }
        Ok(Step::Need)
    }
}

/// The contribution of one decoded fragment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fragment<T> {
    /// Bytes to append to the current message.
    Part {
        /// Fragment payload.
        data: Vec<u8>,
        /// Whether this completes the message.
        last: bool,
    },
    /// A control item that passes through without changing the assembly.
    Whole(T),
}
/// A completed message or a control item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Assembled<T> {
    /// The joined fragment bytes.
    Message(Vec<u8>),
    /// An unchanged control item.
    Whole(T),
}
/// Why fragment assembly failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AssembleError<E> {
    /// The fragment decoder failed.
    Inner(E),
    /// The message exceeded its limit.
    TooLong {
        /// Maximum message bytes.
        limit: usize,
    },
    /// Storage for the message could not be allocated.
    Allocation,
    /// The stream ended before the final fragment, even for an empty message.
    Incomplete {
        /// Payload bytes awaiting a final fragment.
        held: usize,
    },
}
impl<E: fmt::Display> fmt::Display for AssembleError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Inner(e) => write!(f, "fragment decoder: {e}"),
            Self::TooLong { limit } => write!(f, "assembly exceeds {limit} bytes"),
            Self::Allocation => f.write_str("assembly allocation failed"),
            Self::Incomplete { held } => write!(f, "incomplete assembly of {held} bytes"),
        }
    }
}
impl<E: Error> Error for AssembleError<E> {}
/// Joins fragments under one message limit. Control items pass through.
pub struct Assemble<D, F> {
    inner: D,
    f: F,
    buf: Vec<u8>,
    limit: usize,
    active: bool,
}
impl<D, F> Assemble<D, F> {
    /// Creates an assembler. `limit` bounds the retained message bytes and
    /// is clamped to [`Buffer::MAX_LIMIT`].
    pub fn new(inner: D, limit: usize, f: F) -> Self {
        Self {
            inner,
            f,
            buf: Vec::new(),
            limit: limit.min(Buffer::MAX_LIMIT),
            active: false,
        }
    }
}
impl<D: Decode, T, F: FnMut(D::Item) -> Fragment<T>> Decode for Assemble<D, F> {
    type Item = Assembled<T>;
    type Error = AssembleError<D::Error>;
    const NAME: &'static str = D::NAME;
    fn capacity(&self) -> usize {
        self.inner.capacity()
    }
    fn held(&self) -> usize {
        self.buf.len().saturating_add(self.inner.held())
    }
    fn decode(&mut self, input: &[u8], eof: bool) -> Result<Step<Self::Item>, Self::Error> {
        match self
            .inner
            .decode(input, eof)
            .map_err(AssembleError::Inner)?
        {
            Step::Item(item, n) => match (self.f)(item) {
                Fragment::Whole(item) => Ok(Step::Item(Assembled::Whole(item), n)),
                Fragment::Part { data, last } => {
                    if data.len() > self.limit.saturating_sub(self.buf.len()) {
                        return Err(AssembleError::TooLong { limit: self.limit });
                    }
                    // Geometric growth, capped by the named message limit.
                    let size = self.buf.len().saturating_add(data.len());
                    if size > self.buf.capacity() {
                        let target = size
                            .max(self.buf.capacity().saturating_mul(2))
                            .min(self.limit);
                        if self
                            .buf
                            .try_reserve_exact(target.saturating_sub(self.buf.len()))
                            .is_err()
                        {
                            return Err(AssembleError::Allocation);
                        }
                    }
                    self.buf.extend_from_slice(&data);
                    self.active = !last;
                    Ok(if last {
                        Step::Item(Assembled::Message(core::mem::take(&mut self.buf)), n)
                    } else {
                        Step::Skip(n)
                    })
                }
            },
            Step::Skip(n) => Ok(Step::Skip(n)),
            Step::Need if eof && input.is_empty() && self.active => {
                Err(AssembleError::Incomplete {
                    held: self.buf.len(),
                })
            }
            Step::End if self.active => Err(AssembleError::Incomplete {
                held: self.buf.len(),
            }),
            Step::Need => Ok(Step::Need),
            Step::End => Ok(Step::End),
        }
    }
}
