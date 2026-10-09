//! Support for generated wire codecs.

/// Defines a generated module's error type and wire runtime.
///
/// The arguments name the local error type, runtime module, and message,
/// nesting, allocation, and node limits. Each invocation defines distinct
/// types and uses the supplied schema limits. Sampling and contract helpers
/// compile only when tests are enabled in the consuming crate.
#[macro_export]
macro_rules! generated_runtime {
    ($error:ident, $wire:ident, $max_message:ident, $max_depth:ident,
     $max_allocation:ident, $max_nodes:ident) => {
        /// Why a wire value was refused.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $error {
            /// Input ended within a value.
            Truncated,
            /// Input contains bytes after the value.
            Trailing,
            /// A byte, item, allocation, or work limit was exceeded.
            Limit,
            /// The value exceeds the nesting limit.
            Depth,
            /// A scalar, range, flag, enum, set, or null encoding is invalid.
            Value,
            /// Text is not UTF-8.
            Utf8,
            /// A header does not match its declared magic, tag, version, or constant.
            Header,
            /// A block length does not hold the block's fixed fields.
            Layout,
            /// Memory reservation failed.
            Allocation,
        }
        impl std::fmt::Display for $error {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl std::error::Error for $error {}

        #[allow(dead_code)]
        mod $wire {
            use super::{$error, $max_allocation, $max_depth, $max_message, $max_nodes};

            // The IR allows at most 256 magic bytes and an eight-byte prefix.
            const MAX_HEADER: usize = 264;

            pub trait Codec: Sized {
                fn read(r: &mut Reader<'_>, le: bool) -> Result<Self, $error>;
                fn encode(&self, w: &mut Writer, le: bool) -> Result<(), $error>;
                #[cfg(test)]
                fn sample(s: &mut Sampler) -> Result<Self, $error>;
            }
            pub trait Scalar: Copy + PartialOrd {
                fn read(r: &mut Reader<'_>, le: bool) -> Result<Self, $error>;
                fn encode(self, w: &mut Writer, le: bool) -> Result<(), $error>;
                fn same(self, other: Self) -> bool;
            }
            macro_rules! scalar {
                ($t:ty, $valid:expr, $same:expr) => {
                    impl Scalar for $t {
                        fn read(r: &mut Reader<'_>, le: bool) -> Result<Self, $error> {
                            let b = r.take(std::mem::size_of::<Self>())?;
                            let a = b.try_into().map_err(|_| $error::Truncated)?;
                            let v = if le {
                                Self::from_le_bytes(a)
                            } else {
                                Self::from_be_bytes(a)
                            };
                            if !($valid)(v) {
                                return Err($error::Value);
                            }
                            Ok(v)
                        }
                        fn encode(self, w: &mut Writer, le: bool) -> Result<(), $error> {
                            if !($valid)(self) {
                                return Err($error::Value);
                            }
                            w.put(&if le {
                                self.to_le_bytes()
                            } else {
                                self.to_be_bytes()
                            })
                        }
                        fn same(self, other: Self) -> bool {
                            ($same)(self, other)
                        }
                    }
                };
            }
            scalar!(u8, |_: u8| true, |a: u8, b: u8| a == b);
            scalar!(u16, |_: u16| true, |a: u16, b: u16| a == b);
            scalar!(u32, |_: u32| true, |a: u32, b: u32| a == b);
            scalar!(u64, |_: u64| true, |a: u64, b: u64| a == b);
            scalar!(i8, |_: i8| true, |a: i8, b: i8| a == b);
            scalar!(i16, |_: i16| true, |a: i16, b: i16| a == b);
            scalar!(i32, |_: i32| true, |a: i32, b: i32| a == b);
            scalar!(i64, |_: i64| true, |a: i64, b: i64| a == b);
            scalar!(f32, f32::is_finite, |a: f32, b: f32| a.to_bits()
                == b.to_bits());
            scalar!(f64, f64::is_finite, |a: f64, b: f64| a.to_bits()
                == b.to_bits());

            #[derive(Default)]
            struct Budget {
                depth: usize,
                nodes: usize,
                allocated: usize,
            }
            impl Budget {
                fn enter(&mut self) -> Result<(), $error> {
                    if self.depth >= $max_depth {
                        return Err($error::Depth);
                    }
                    if self.nodes >= $max_nodes {
                        return Err($error::Limit);
                    }
                    self.depth += 1;
                    self.nodes += 1;
                    Ok(())
                }
                fn charge(&mut self, bytes: usize) -> Result<(), $error> {
                    self.allocated = self.allocated.checked_add(bytes).ok_or($error::Limit)?;
                    if self.allocated > $max_allocation {
                        return Err($error::Limit);
                    }
                    Ok(())
                }
            }
            pub struct Reader<'a> {
                bytes: &'a [u8],
                pos: usize,
                budget: Budget,
            }
            impl<'a> Reader<'a> {
                pub fn new(bytes: &'a [u8]) -> Self {
                    Self {
                        bytes,
                        pos: 0,
                        budget: Budget::default(),
                    }
                }
                pub fn nested<T>(
                    &mut self,
                    f: impl FnOnce(&mut Self) -> Result<T, $error>,
                ) -> Result<T, $error> {
                    self.budget.enter()?;
                    let result = f(self);
                    self.budget.depth -= 1;
                    result
                }
                pub fn take(&mut self, n: usize) -> Result<&'a [u8], $error> {
                    let end = self.pos.checked_add(n).ok_or($error::Limit)?;
                    let bytes = self.bytes.get(self.pos..end).ok_or($error::Truncated)?;
                    self.pos = end;
                    Ok(bytes)
                }
                pub fn scalar<T: Scalar>(&mut self, le: bool) -> Result<T, $error> {
                    T::read(self, le)
                }
                pub fn position(&self) -> usize {
                    self.pos
                }
                pub fn unsigned(&mut self, width: usize, le: bool) -> Result<u64, $error> {
                    match width {
                        1 => Ok(u64::from(self.scalar::<u8>(le)?)),
                        2 => Ok(u64::from(self.scalar::<u16>(le)?)),
                        4 => Ok(u64::from(self.scalar::<u32>(le)?)),
                        8 => self.scalar::<u64>(le),
                        _ => Err($error::Value),
                    }
                }
                /// Skips ignored bytes up to `offset` bytes after `start`.
                pub fn skip_to(&mut self, start: usize, offset: usize) -> Result<(), $error> {
                    let target = start.checked_add(offset).ok_or($error::Limit)?;
                    let n = target.checked_sub(self.pos).ok_or($error::Layout)?;
                    self.take(n).map(|_| ())
                }
                /// Starts a block of `length` bytes that must hold `fixed` bytes.
                pub fn block(&mut self, length: usize, fixed: usize) -> Result<usize, $error> {
                    if length < fixed {
                        return Err($error::Layout);
                    }
                    let end = self.pos.checked_add(length).ok_or($error::Limit)?;
                    if end > self.bytes.len() {
                        return Err($error::Truncated);
                    }
                    Ok(self.pos)
                }
                pub fn ranged<T: Scalar>(&mut self, min: T, max: T, le: bool) -> Result<T, $error> {
                    let v = self.scalar::<T>(le)?;
                    if v < min || v > max {
                        return Err($error::Value);
                    }
                    Ok(v)
                }
                pub fn count(
                    &mut self,
                    width: usize,
                    le: bool,
                    limit: usize,
                ) -> Result<usize, $error> {
                    let n = self.unsigned(width, le)?;
                    let n = usize::try_from(n).map_err(|_| $error::Limit)?;
                    if n > limit {
                        return Err($error::Limit);
                    }
                    Ok(n)
                }
                pub fn bytes(
                    &mut self,
                    width: usize,
                    size: usize,
                    le: bool,
                ) -> Result<Vec<u8>, $error> {
                    let n = if width == 0 {
                        size
                    } else {
                        self.count(width, le, size)?
                    };
                    let b = self.take(n)?;
                    self.budget.charge(n)?;
                    let mut v = Vec::new();
                    v.try_reserve_exact(n).map_err(|_| $error::Allocation)?;
                    v.extend_from_slice(b);
                    Ok(v)
                }
                pub fn text(
                    &mut self,
                    width: usize,
                    size: usize,
                    le: bool,
                ) -> Result<String, $error> {
                    String::from_utf8(self.bytes(width, size, le)?).map_err(|_| $error::Utf8)
                }
                pub fn reference<T: Codec>(&mut self, le: bool) -> Result<Box<T>, $error> {
                    self.budget.charge(std::mem::size_of::<T>())?;
                    Ok(Box::new(T::read(self, le)?))
                }
                pub fn group<T>(
                    &mut self,
                    width: usize,
                    limit: usize,
                    minimum: usize,
                    le: bool,
                    f: impl FnMut(&mut Self) -> Result<T, $error>,
                ) -> Result<Vec<T>, $error> {
                    let n = self.count(width, le, limit)?;
                    self.entries(n, minimum, f)
                }
                /// Reads `n` counted entries of at least `minimum` bytes each.
                pub fn entries<T>(
                    &mut self,
                    n: usize,
                    minimum: usize,
                    mut f: impl FnMut(&mut Self) -> Result<T, $error>,
                ) -> Result<Vec<T>, $error> {
                    let remaining = self.bytes.len().saturating_sub(self.pos);
                    if minimum != 0 && n > remaining / minimum {
                        return Err($error::Truncated);
                    }
                    let bytes = n
                        .checked_mul(std::mem::size_of::<T>())
                        .ok_or($error::Limit)?;
                    self.budget.charge(bytes)?;
                    if n > $max_nodes.saturating_sub(self.budget.nodes) {
                        return Err($error::Limit);
                    }
                    let mut v = Vec::new();
                    v.try_reserve_exact(n).map_err(|_| $error::Allocation)?;
                    for _ in 0..n {
                        v.push(self.nested(&mut f)?);
                    }
                    Ok(v)
                }
                pub fn optional<T>(
                    &mut self,
                    width: usize,
                    le: bool,
                    f: impl FnOnce(&mut Self) -> Result<T, $error>,
                ) -> Result<Option<T>, $error> {
                    let flag = match width {
                        1 => u64::from(self.scalar::<u8>(le)?),
                        2 => u64::from(self.scalar::<u16>(le)?),
                        4 => u64::from(self.scalar::<u32>(le)?),
                        8 => self.scalar::<u64>(le)?,
                        _ => return Err($error::Value),
                    };
                    match flag {
                        0 => Ok(None),
                        1 => self.nested(f).map(Some),
                        _ => Err($error::Value),
                    }
                }
                pub fn nullable<T: Scalar>(
                    &mut self,
                    null: T,
                    le: bool,
                ) -> Result<Option<T>, $error> {
                    let v = self.scalar::<T>(le)?;
                    Ok(if v.same(null) { None } else { Some(v) })
                }
                pub fn nullable_range<T: Scalar>(
                    &mut self,
                    null: T,
                    min: T,
                    max: T,
                    le: bool,
                ) -> Result<Option<T>, $error> {
                    let v = self.scalar::<T>(le)?;
                    if v.same(null) {
                        return Ok(None);
                    }
                    if v < min || v > max {
                        return Err($error::Value);
                    }
                    Ok(Some(v))
                }
                /// Reads `None` for the null value, or else rereads the value with `f`.
                pub fn nullable_ref<S: Scalar, T>(
                    &mut self,
                    null: S,
                    le: bool,
                    f: impl FnOnce(&mut Self) -> Result<T, $error>,
                ) -> Result<Option<T>, $error> {
                    let start = self.pos;
                    if self.scalar::<S>(le)?.same(null) {
                        return Ok(None);
                    }
                    self.pos = start;
                    f(self).map(Some)
                }
            }
            /// Reads an unsigned header field and refuses values above `max`.
            pub fn field(
                header: &[u8],
                offset: usize,
                width: usize,
                le: bool,
                max: u64,
            ) -> Result<u64, $error> {
                let end = offset.checked_add(width).ok_or($error::Limit)?;
                let mut r = Reader::new(header.get(offset..end).ok_or($error::Truncated)?);
                let v = r.unsigned(width, le)?;
                if v > max {
                    return Err($error::Value);
                }
                Ok(v)
            }
            /// Writes an unsigned header field. Refuses values wider than `width`.
            pub fn put_field(
                header: &mut [u8],
                offset: usize,
                width: usize,
                le: bool,
                value: u64,
            ) -> Result<(), $error> {
                if width < 8 && value >> (width * 8) != 0 {
                    return Err($error::Limit);
                }
                let end = offset.checked_add(width).ok_or($error::Limit)?;
                let bytes = if le {
                    value.to_le_bytes()
                } else {
                    value.to_be_bytes()
                };
                let source = if le {
                    bytes.get(..width)
                } else {
                    bytes.get(8usize.checked_sub(width).ok_or($error::Limit)?..)
                }
                .ok_or($error::Limit)?;
                let target = header.get_mut(offset..end).ok_or($error::Limit)?;
                if target.len() != source.len() {
                    return Err($error::Limit);
                }
                target.copy_from_slice(source);
                Ok(())
            }
            pub struct Writer {
                bytes: Vec<u8>,
                budget: Budget,
            }
            impl Writer {
                pub fn nested(
                    &mut self,
                    f: impl FnOnce(&mut Self) -> Result<(), $error>,
                ) -> Result<(), $error> {
                    self.budget.enter()?;
                    let result = f(self);
                    self.budget.depth -= 1;
                    result
                }
                pub fn put(&mut self, b: &[u8]) -> Result<(), $error> {
                    let end = self.bytes.len().checked_add(b.len()).ok_or($error::Limit)?;
                    if end > $max_message {
                        return Err($error::Limit);
                    }
                    self.bytes
                        .try_reserve(b.len())
                        .map_err(|_| $error::Allocation)?;
                    self.bytes.extend_from_slice(b);
                    Ok(())
                }
                pub fn scalar<T: Scalar>(&mut self, value: T, le: bool) -> Result<(), $error> {
                    value.encode(self, le)
                }
                pub fn position(&self) -> usize {
                    self.bytes.len()
                }
                /// Writes zero bytes up to `offset` bytes after `start`.
                pub fn pad_to(&mut self, start: usize, offset: usize) -> Result<(), $error> {
                    let target = start.checked_add(offset).ok_or($error::Limit)?;
                    let n = target.checked_sub(self.bytes.len()).ok_or($error::Layout)?;
                    if target > $max_message {
                        return Err($error::Limit);
                    }
                    self.bytes.try_reserve(n).map_err(|_| $error::Allocation)?;
                    self.bytes.resize(target, 0);
                    Ok(())
                }
                pub fn ranged<T: Scalar>(
                    &mut self,
                    v: T,
                    min: T,
                    max: T,
                    le: bool,
                ) -> Result<(), $error> {
                    if v < min || v > max {
                        return Err($error::Value);
                    }
                    self.scalar(v, le)
                }
                pub fn count(&mut self, n: usize, width: usize, le: bool) -> Result<(), $error> {
                    match width {
                        1 => self.scalar(u8::try_from(n).map_err(|_| $error::Limit)?, le),
                        2 => self.scalar(u16::try_from(n).map_err(|_| $error::Limit)?, le),
                        4 => self.scalar(u32::try_from(n).map_err(|_| $error::Limit)?, le),
                        8 => self.scalar(u64::try_from(n).map_err(|_| $error::Limit)?, le),
                        _ => Err($error::Value),
                    }
                }
                pub fn bytes(
                    &mut self,
                    b: &[u8],
                    width: usize,
                    size: usize,
                    le: bool,
                ) -> Result<(), $error> {
                    if (width == 0 && b.len() != size) || b.len() > size {
                        return Err($error::Limit);
                    }
                    self.budget.charge(b.len())?;
                    if width != 0 {
                        self.count(b.len(), width, le)?;
                    }
                    self.put(b)
                }
                pub fn reference<T: Codec>(&mut self, value: &T, le: bool) -> Result<(), $error> {
                    self.budget.charge(std::mem::size_of::<T>())?;
                    value.encode(self, le)
                }
                pub fn group<T>(
                    &mut self,
                    values: &[T],
                    width: usize,
                    limit: usize,
                    le: bool,
                    f: impl FnMut(&mut Self, &T) -> Result<(), $error>,
                ) -> Result<(), $error> {
                    self.check_entries(values, limit)?;
                    self.count(values.len(), width, le)?;
                    self.entries(values, limit, f)
                }
                fn check_entries<T>(&mut self, values: &[T], limit: usize) -> Result<(), $error> {
                    if values.len() > limit
                        || values.len() > $max_nodes.saturating_sub(self.budget.nodes)
                    {
                        return Err($error::Limit);
                    }
                    Ok(())
                }
                /// Writes counted entries whose count was written by the caller.
                pub fn entries<T>(
                    &mut self,
                    values: &[T],
                    limit: usize,
                    mut f: impl FnMut(&mut Self, &T) -> Result<(), $error>,
                ) -> Result<(), $error> {
                    self.check_entries(values, limit)?;
                    let bytes = values
                        .len()
                        .checked_mul(std::mem::size_of::<T>())
                        .ok_or($error::Limit)?;
                    self.budget.charge(bytes)?;
                    for v in values {
                        self.nested(|w| f(w, v))?;
                    }
                    Ok(())
                }
                pub fn optional<T>(
                    &mut self,
                    value: &Option<T>,
                    width: usize,
                    le: bool,
                    f: impl FnOnce(&mut Self, &T) -> Result<(), $error>,
                ) -> Result<(), $error> {
                    self.count(usize::from(value.is_some()), width, le)?;
                    match value {
                        Some(v) => self.nested(|w| f(w, v)),
                        None => Ok(()),
                    }
                }
                pub fn nullable<T: Scalar>(
                    &mut self,
                    value: &Option<T>,
                    null: T,
                    le: bool,
                ) -> Result<(), $error> {
                    match value {
                        Some(v) if v.same(null) => Err($error::Value),
                        Some(v) => self.scalar(*v, le),
                        None => self.scalar(null, le),
                    }
                }
                pub fn nullable_range<T: Scalar>(
                    &mut self,
                    value: &Option<T>,
                    null: T,
                    min: T,
                    max: T,
                    le: bool,
                ) -> Result<(), $error> {
                    match value {
                        Some(v) if v.same(null) => Err($error::Value),
                        Some(v) => self.ranged(*v, min, max, le),
                        None => self.scalar(null, le),
                    }
                }
                /// Writes the null value for `None`. Values never encode as null.
                pub fn nullable_ref<S: Scalar, T>(
                    &mut self,
                    value: &Option<T>,
                    null: S,
                    le: bool,
                    f: impl FnOnce(&mut Self, &T) -> Result<(), $error>,
                ) -> Result<(), $error> {
                    match value {
                        Some(v) => f(self, v),
                        None => self.scalar(null, le),
                    }
                }
            }
            #[cfg(test)]
            pub struct Sampler {
                pub rng: fictionet::stdlib::codec::Lcg,
                budget: Budget,
                minimal: bool,
            }
            #[cfg(test)]
            impl Sampler {
                pub fn number(&mut self) -> u64 {
                    (self.rng.next() << 33) | (self.rng.next() << 2) | self.rng.below(4)
                }
                pub fn seed(seed: u64) -> Self {
                    Self {
                        rng: fictionet::stdlib::codec::Lcg::new(seed),
                        budget: Budget::default(),
                        minimal: seed == 0,
                    }
                }
                pub fn nested<T>(
                    &mut self,
                    f: impl FnOnce(&mut Self) -> Result<T, $error>,
                ) -> Result<T, $error> {
                    self.budget.enter()?;
                    let result = f(self);
                    self.budget.depth -= 1;
                    result
                }
                pub fn bytes(&mut self, width: usize, size: usize) -> Result<Vec<u8>, $error> {
                    let n = if width == 0 {
                        size
                    } else if self.minimal {
                        0
                    } else {
                        self.rng.index(size.min(8).saturating_add(1))
                    };
                    self.budget.charge(n)?;
                    let mut bytes = Vec::new();
                    bytes.try_reserve_exact(n).map_err(|_| $error::Allocation)?;
                    bytes.resize(n, 0);
                    self.rng.fill(&mut bytes);
                    Ok(bytes)
                }
                pub fn text(&mut self, width: usize, size: usize) -> Result<String, $error> {
                    let mut bytes = self.bytes(width, size)?;
                    for b in &mut bytes {
                        *b = b'a' + *b % 26;
                    }
                    String::from_utf8(bytes).map_err(|_| $error::Utf8)
                }
                pub fn reference<T: Codec>(&mut self) -> Result<Box<T>, $error> {
                    self.budget.charge(std::mem::size_of::<T>())?;
                    Ok(Box::new(T::sample(self)?))
                }
                pub fn group<T>(
                    &mut self,
                    limit: usize,
                    mut f: impl FnMut(&mut Self) -> Result<T, $error>,
                ) -> Result<Vec<T>, $error> {
                    let n = if !self.minimal && self.budget.depth < 4 {
                        self.rng.index(limit.min(2).saturating_add(1))
                    } else {
                        0
                    };
                    self.budget.charge(
                        n.checked_mul(std::mem::size_of::<T>())
                            .ok_or($error::Limit)?,
                    )?;
                    let mut values = Vec::new();
                    values
                        .try_reserve_exact(n)
                        .map_err(|_| $error::Allocation)?;
                    for _ in 0..n {
                        values.push(self.nested(&mut f)?);
                    }
                    Ok(values)
                }
                pub fn optional<T>(
                    &mut self,
                    f: impl FnOnce(&mut Self) -> Result<T, $error>,
                ) -> Result<Option<T>, $error> {
                    if !self.minimal && self.budget.depth < 4 && self.rng.coin() {
                        self.nested(f).map(Some)
                    } else {
                        Ok(None)
                    }
                }
                pub fn nullable<T: Scalar>(
                    &mut self,
                    value: T,
                    null: T,
                ) -> Result<Option<T>, $error> {
                    Ok(if value.same(null) || self.rng.coin() {
                        None
                    } else {
                        Some(value)
                    })
                }
                /// A uniform-ish value in `min..=max`.
                pub fn ranged(&mut self, min: i128, max: i128) -> i128 {
                    let span = max.saturating_sub(min).saturating_add(1).max(1);
                    let offset = i128::from(self.number()) % span;
                    min.saturating_add(offset)
                }
                pub fn maybe<T>(
                    &mut self,
                    f: impl FnOnce(&mut Self) -> Result<T, $error>,
                ) -> Result<Option<T>, $error> {
                    if !self.minimal && self.rng.coin() {
                        f(self).map(Some)
                    } else {
                        Ok(None)
                    }
                }
            }
            #[cfg(test)]
            pub fn check<T>() -> Result<(), $error>
            where
                T: Codec
                    + fictionet::stdlib::codec::Wire<ParseError = $error, WriteError = $error>
                    + std::fmt::Debug
                    + PartialEq,
            {
                use fictionet::stdlib::test_support::contract;
                let mut successes = 0;
                for seed in 0..32 {
                    let mut s = Sampler::seed(seed);
                    if let Ok(value) = T::sample(&mut s) {
                        contract::check_wire_value(&value);
                        if let Ok(bytes) = value.to_bytes() {
                            assert_eq!(T::parse(&bytes)?, value);
                            successes += 1;
                        }
                    }
                }
                assert!(
                    successes > 0,
                    "no writable sample for {}",
                    std::any::type_name::<T>()
                );
                Ok(())
            }
            #[cfg(test)]
            pub fn check_stream<T, D>(
                make: impl Fn() -> D,
                write: fn(&T, &mut Vec<u8>) -> Result<(), $error>,
                header: usize,
            ) where
                T: Codec + std::fmt::Debug + PartialEq,
                D: fictionet::stdlib::codec::Decode<Item = T, Error = $error>,
            {
                use fictionet::stdlib::test_support::contract;
                let mut successes = 0;
                for seed in 0..32 {
                    let mut s = Sampler::seed(seed);
                    if let Ok(value) = T::sample(&mut s) {
                        let mut bytes = Vec::new();
                        if write(&value, &mut bytes).is_ok() {
                            contract::check_decode_with_alloc_limit(
                                &make,
                                &bytes,
                                2 * ($max_message + header),
                            );
                            successes += 1;
                        }
                    }
                }
                assert!(
                    successes > 0,
                    "no writable frame for {}",
                    std::any::type_name::<D>()
                );
            }
            pub fn parse<T: Codec>(bytes: &[u8], le: bool) -> Result<T, $error> {
                if bytes.len() > $max_message {
                    return Err($error::Limit);
                }
                let mut r = Reader::new(bytes);
                let value = T::read(&mut r, le)?;
                if r.pos != bytes.len() {
                    return Err($error::Trailing);
                }
                Ok(value)
            }
            pub fn write<T: Codec>(value: &T, out: &mut Vec<u8>, le: bool) -> Result<(), $error> {
                let mut w = Writer {
                    bytes: Vec::new(),
                    budget: Budget::default(),
                };
                value.encode(&mut w, le)?;
                out.len().checked_add(w.bytes.len()).ok_or($error::Limit)?;
                out.try_reserve(w.bytes.len())
                    .map_err(|_| $error::Allocation)?;
                out.extend_from_slice(&w.bytes);
                Ok(())
            }
            pub fn frame<T: Codec>(
                input: &[u8],
                magic: &[u8],
                width: usize,
                prefix_le: bool,
                body_le: bool,
            ) -> Result<fictionet::stdlib::codec::Step<T>, $error> {
                use fictionet::stdlib::codec::Step;
                let header = magic.len().checked_add(width).ok_or($error::Limit)?;
                let Some(prefix) = input.get(..header) else {
                    return Ok(Step::Need);
                };
                if prefix.get(..magic.len()) != Some(magic) {
                    return Err($error::Header);
                }
                let mut r = Reader::new(prefix.get(magic.len()..).ok_or($error::Truncated)?);
                let n = r.count(width, prefix_le, $max_message)?;
                let end = header.checked_add(n).ok_or($error::Limit)?;
                let Some(body) = input.get(header..end) else {
                    return Ok(Step::Need);
                };
                Ok(Step::Item(parse(body, body_le)?, end))
            }
            pub fn write_frame<T: Codec>(
                value: &T,
                out: &mut Vec<u8>,
                magic: &[u8],
                width: usize,
                prefix_le: bool,
                body_le: bool,
            ) -> Result<(), $error> {
                let mut body = Vec::new();
                write(value, &mut body, body_le)?;
                let mut header = Writer {
                    bytes: Vec::new(),
                    budget: Budget::default(),
                };
                // Header storage is at most 264 bytes, independent of the body limit.
                header
                    .bytes
                    .try_reserve_exact(MAX_HEADER)
                    .map_err(|_| $error::Allocation)?;
                header.bytes.extend_from_slice(magic);
                let n = u64::try_from(body.len()).map_err(|_| $error::Limit)?;
                let bytes = if prefix_le {
                    n.to_le_bytes()
                } else {
                    n.to_be_bytes()
                };
                if width < 8 && n >= (1u64 << (width * 8)) {
                    return Err($error::Limit);
                }
                let prefix = if prefix_le {
                    bytes.get(..width)
                } else {
                    bytes.get(8usize.checked_sub(width).ok_or($error::Limit)?..)
                }
                .ok_or($error::Limit)?;
                header.bytes.extend_from_slice(prefix);
                let total = header
                    .bytes
                    .len()
                    .checked_add(body.len())
                    .ok_or($error::Limit)?;
                out.len().checked_add(total).ok_or($error::Limit)?;
                out.try_reserve(total).map_err(|_| $error::Allocation)?;
                out.extend_from_slice(&header.bytes);
                out.extend_from_slice(&body);
                Ok(())
            }
        }
    };
}
