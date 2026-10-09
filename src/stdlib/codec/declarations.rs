//! Declarations for protocol errors and framing metadata.

/// Implements error formatting from local match arms and an empty error chain.
#[macro_export]
macro_rules! error_display {
    ($error:ty, $f:ident, {$($arms:tt)*}) => {
        impl core::fmt::Display for $error {
            fn fmt(&self, $f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                match self { $($arms)* }
            }
        }
        impl core::error::Error for $error {}
    };
}

/// Converts a cursor error with the caller's expression and preserves its payload.
#[macro_export]
macro_rules! codec_from {
    ($error:ty, $source:ty, |$value:pat_param| $body:expr) => {
        impl From<$source> for $error {
            #[inline]
            fn from($value: $source) -> Self {
                $body
            }
        }
    };
}

/// Implements prefix framing with local limits, capacity, and parser items.
/// Metadata bodies retain their protocol's payload or whole-frame limit rules.
/// Omitting `normalize` keeps the supplied limit unchanged.
#[macro_export]
macro_rules! prefixed {
    ($(#[$attr:meta])* $ty:ty => ($item:ty, $error:ty, $limit:ty);
     name = $name:expr;
     default $default:block
     $(normalize($n:pat_param) $normalize:block)?
     capacity($c:pat_param) $capacity:block
     $($parser:item)*) => {
        $(#[$attr])*
        impl fictionet::stdlib::codec::Prefixed for $ty {
            type Item = $item;
            type Error = $error;
            type Limit = $limit;
            const NAME: &'static str = $name;
            #[inline]
            fn default_limit() -> Self::Limit { $default }
            $(#[inline]
            fn normalize_limit($n: Self::Limit) -> Self::Limit { $normalize })?
            #[inline]
            fn capacity($c: &Self::Limit) -> usize { $capacity }
            $($parser)*
        }
    };
}

/// Declares local fixed-width fields, cursor reads, and integer encodings.
/// A read advances the cursor before validating the field. Integer reads
/// require exactly their width; conversion methods select byte order.
#[macro_export]
macro_rules! fixed_fields {
    ($field:ident, $take:ident, $array:ident; $error:ty, $length:expr;
     $from:ident, $to:ident; $($ty:ty),+ $(,)?) => {
        trait $field: Sized {
            const LEN: usize;
            fn get(b: &[u8]) -> Result<Self, $error>;
            fn put(&self, out: &mut Vec<u8>);
        }
        fn $take<T: $field>(b: &mut &[u8]) -> Result<T, $error> {
            let (head, rest) = b.split_at_checked(T::LEN).ok_or($length)?;
            *b = rest;
            T::get(head)
        }
        fn $array<const N: usize>(b: &[u8]) -> Result<[u8; N], $error> {
            b.try_into().map_err(|_| $length)
        }
        $(impl $field for $ty {
            const LEN: usize = core::mem::size_of::<$ty>();
            fn get(b: &[u8]) -> Result<Self, $error> { Ok(<$ty>::$from($array(b)?)) }
            fn put(&self, out: &mut Vec<u8>) { out.extend_from_slice(&self.$to()); }
        })*
    };
}

/// Implements bounded text parsing and transactional formatting with local validation.
/// The type supplies `read_value` and `format_value`; method docs stay at the call.
#[macro_export]
macro_rules! text_wire {
    ($error:ident, $limit:ident, $ty:ty, $(#[$parse:meta])* parse, $(#[$write:meta])* write) => {
        impl fictionet::stdlib::codec::Wire for $ty {
            type ParseError = $error;
            type WriteError = $error;

            $(#[$parse])*
            fn parse(bytes: &[u8]) -> Result<Self, $error> {
                if bytes.len() > $limit {
                    return Err($error::TooLong);
                }
                let text = core::str::from_utf8(bytes).map_err(|_| $error::Utf8)?;
                let value = Self::read_value(text)?;
                value.write(&mut Vec::new())?;
                Ok(value)
            }

            $(#[$write])*
            fn write(&self, out: &mut Vec<u8>) -> Result<(), $error> {
                let text = self.format_value()?;
                if text.len() > $limit {
                    return Err($error::TooLong);
                }
                if Self::read_value(&text)? != *self {
                    return Err($error::Unwritable);
                }
                out.extend_from_slice(text.as_bytes());
                Ok(())
            }
        }
    };
}

/// Declares an open numeric enum with reversible code conversion.
/// Named variants and the raw fallback keep their supplied attributes and docs.
#[macro_export]
macro_rules! open_enum {
    ($(#[$attr:meta])* pub enum $name:ident: $raw:ty {
        $($(#[$doc:meta])* $variant:ident = $code:literal,)*
        ; $(#[$other:meta])* Other,
    }
    [$(#[$code_doc:meta])*] [$(#[$from_doc:meta])*]) => {
        $(#[$attr])*
        pub enum $name { $($(#[$doc])* $variant,)* $(#[$other])* Other($raw) }
        impl $name {
            $(#[$code_doc])*
            pub fn code(self) -> $raw {
                match self { $(Self::$variant => $code,)* Self::Other(c) => c }
            }
            $(#[$from_doc])*
            pub fn from_code(code: $raw) -> Self {
                match code { $($code => Self::$variant,)* c => Self::Other(c) }
            }
        }
    };
}
