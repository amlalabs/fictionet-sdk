//! Fixed-layout message tables.

/// Defines message structs and a direction enum with checked field lengths.
///
/// Field and envelope operations are local paths or expressions. `read` returns
/// the kind and body; `check` validates the whole input against the fixed size.
/// `write` checks and writes the envelope after tail validation. `unknown` reads
/// an unrecognized kind. Optional variants supply kind, length and write hooks;
/// their writer receives the enum's known kinds. `items` adds local trait impls.
/// Common fields precede row fields. Common tails and row tails follow them.
/// Tail operations are read, check, length and write, in that order.
/// A row tail starts with `=>` and uses `tail_ops`. `access` lists header
/// accessors; `length` names the optional kind-to-length lookup. `prefix`
/// counts envelope bytes outside the fields in the length assertion.
///
/// ```
/// use fictionet::stdlib::codec::{layout, Wire};
/// # type Error = std::io::Error;
/// # fn bad(_: u8) -> Error { Error::from(std::io::ErrorKind::InvalidData) }
/// # trait Field { const LEN: usize; fn put(&self, out: &mut Vec<u8>); }
/// # impl Field for u8 {
/// #     const LEN: usize = 1;
/// #     fn put(&self, out: &mut Vec<u8>) { out.push(*self); }
/// # }
/// # fn take(b: &mut &[u8]) -> Result<u8, Error> {
/// #     let (&n, rest) = b.split_first().ok_or_else(|| bad(0))?;
/// #     *b = rest;
/// #     Ok(n)
/// # }
/// # fn read(b: &[u8]) -> Result<(u8, &[u8]), Error> {
/// #     let (&kind, body) = b.split_first().ok_or_else(|| bad(0))?;
/// #     Ok((kind, body))
/// # }
/// # fn check(b: &[u8], len: usize) -> Result<(), Error> {
/// #     if b.len() == len { Ok(()) } else { Err(bad(0)) }
/// # }
/// # fn write(kind: u8, len: usize, out: &mut Vec<u8>) -> Result<(), Error> {
/// #     out.reserve(len); out.push(kind); Ok(())
/// # }
/// layout! {
///     error = Error; type_error = bad;
///     field = Field; take = take; put = Field::put; prefix = 1;
///     read = read; check = check; write = write;
///     unknown = |kind, _| Err(bad(kind));
///     message = { [#[derive(Clone, Debug, PartialEq, Eq)]]
///         /// Bytes including the kind.
///         const LEN; pub fn wire_len;
///     };
///     header = {}; tail = {}; tail_ops = (); items = [];
///     access = {}; length = {
///         /// The length for a known kind.
///         length_of
///     }; variants = {};
///     /// Either sample message.
///     #[derive(Clone, Debug, PartialEq, Eq)]
///     Message;
///     /// A ping.
///     Ping = 1, 2 { /// The token.
///         token: u8,
///     }
///     /// A pong.
///     Pong = 2, 2 { /// The token.
///         token: u8,
///     }
/// }
/// assert_eq!(Message::parse(&[1, 7])?, Ping { token: 7 }.into());
/// assert_eq!(Pong { token: 7 }.to_bytes()?, [2, 7]);
/// # Ok::<(), Error>(())
/// ```
#[macro_export]
macro_rules! layout {
    (
        error = $error:ty; type_error = $type_error:path;
        field = $field_trait:path; take = $take:path; put = $put:path; prefix = $prefix:expr;
        read = $read:expr; check = $check:expr; write = $write:expr;
        unknown = $unknown:expr;
        message = $message:tt;
        header = $header:tt; tail = $tail:tt; tail_ops = $tail_ops:tt;
        items = [$($items:path)?]; access = $access:tt;
        length = {$( $(#[$ldoc:meta])* $length:ident )?};
        variants = {$( $(#[$vdoc:meta])* $variant:ident($vty:ty) =>
            ($vkind:expr, $vlen:expr, $vwrite:expr); )*};
        $(#[$edoc:meta])* $enum:ident;
        $(
            $(#[$doc:meta])* $name:ident = $kind:literal, $len:literal {
                $( $(#[$fdoc:meta])* $field:ident: $ty:ty, )*
            } $(=> $(#[$tdoc:meta])* $row_tail:ident: $tty:ty; )?
        )*
    ) => {
        $(
            $crate::layout!(@message $message, $header, $tail,
                $tail_ops, {$( $(#[$tdoc])* $row_tail: $tty; )?},
                ($error, $type_error, $field_trait, $take, $put, $prefix,
                 $read, $check, $write),
                $(#[$doc])* $name = $kind, $len {
                    $( $(#[$fdoc])* $field: $ty, )*
                }
            );
            impl From<$name> for $enum {
                fn from(m: $name) -> Self { Self::$name(m) }
            }
        )*
        $crate::layout!(@items [$($items)?] $enum, $($name),*);
        $(#[$edoc])*
        pub enum $enum {
            $( #[doc = concat!("A [`", stringify!($name), "`].")] $name($name), )*
            $( $(#[$vdoc])* $variant($vty), )*
        }
        impl $enum {
            /// The message type byte.
            pub fn kind(&self) -> u8 {
                match self {
                    $( Self::$name(_) => $kind, )*
                    $( Self::$variant(value) => ($vkind)(value), )*
                }
            }
            /// Bytes on the wire.
            pub fn wire_len(&self) -> usize {
                match self {
                    $( Self::$name(m) => m.wire_len(), )*
                    $( Self::$variant(value) => ($vlen)(value), )*
                }
            }
            /// Every defined message type byte, in specification order.
            pub const KINDS: &'static [u8] = &[$($kind),*];
        }
        $crate::layout!(@length $enum {$( $(#[$ldoc])* $length )?} [$($kind => $len,)*]);
        $crate::layout!(@access $enum $access [$($name),*]);
        impl fictionet::stdlib::codec::Wire for $enum {
            type ParseError = $error;
            type WriteError = $error;
            fn parse(b: &[u8]) -> Result<Self, $error> {
                let (kind, body) = ($read)(b)?;
                match kind {
                    $( $kind => {
                        ($check)(b, $len)?;
                        $name::read_body(body).map(Self::$name)
                    }, )*
                    other => ($unknown)(other, body),
                }
            }
            fn write(&self, out: &mut Vec<u8>) -> Result<(), $error> {
                match self {
                    $( Self::$name(m) => m.write_body(out), )*
                    $( Self::$variant(value) => ($vwrite)(value, Self::KINDS, out), )*
                }
            }
        }
    };
    (@message $message:tt, $header:tt, {$($tail:tt)*}, $ops:tt,
        {$( $(#[$doc:meta])* $field:ident: $ty:ty; )?}, $wire:tt, $($row:tt)*
    ) => {
        $crate::layout!(@struct $message, $header,
            {$($tail)* $( $(#[$doc])* $field: $ty => $ops; )?}, $wire, $($row)*);
    };
    (@struct {[$(#[$derive:meta])*] $(#[$ldoc:meta])* const $length:ident;
        $vis:vis fn wire_len;},
        {$( $(#[$hdoc:meta])* $header:ident: $hty:ty, )*},
        {$( $(#[$tdoc:meta])* $tail:ident: $tty:ty =>
            ($get:expr, $check_tail:expr, $tail_len:expr, $put_tail:expr); )*},
        ($error:ty, $type_error:path, $field_trait:path, $take:path, $put:path,
         $prefix:expr, $read:expr, $check:expr, $write:expr),
        $(#[$doc:meta])* $name:ident = $kind:literal, $len:literal {
            $( $(#[$fdoc:meta])* $field:ident: $ty:ty, )*
        }
    ) => {
        $(#[$doc])* $(#[$derive])*
        pub struct $name {
            $( $(#[$hdoc])* pub $header: $hty, )*
            $( $(#[$fdoc])* pub $field: $ty, )*
            $( $(#[$tdoc])* pub $tail: $tty, )*
        }
        impl $name {
            /// The message type byte.
            pub const KIND: u8 = $kind;
            $(#[$ldoc])* pub const $length: usize = $len;
            fn read_body(mut b: &[u8]) -> Result<Self, $error> {
                let b = &mut b;
                $( let $header = $take(b)?; )*
                $( let $field = $take(b)?; )*
                $( let $tail = ($get)(b)?; )*
                Ok(Self { $($header,)* $($field,)* $($tail,)* })
            }
            /// Bytes on the wire.
            $vis fn wire_len(&self) -> usize {
                $len $(+ ($tail_len)(&self.$tail))*
            }
            fn write_body(&self, out: &mut Vec<u8>) -> Result<(), $error> {
                $( ($check_tail)(&self.$tail)?; )*
                ($write)(Self::KIND, self.wire_len(), out)?;
                $( $put(&self.$header, out); )*
                $( $put(&self.$field, out); )*
                $( ($put_tail)(&self.$tail, out); )*
                Ok(())
            }
        }
        const _: () = assert!($prefix $(+ <$hty as $field_trait>::LEN)*
            $(+ <$ty as $field_trait>::LEN)* == $len);
        impl fictionet::stdlib::codec::Wire for $name {
            type ParseError = $error;
            type WriteError = $error;
            fn parse(b: &[u8]) -> Result<Self, $error> {
                let (kind, body) = ($read)(b)?;
                if kind != $kind { return Err($type_error(kind)); }
                ($check)(b, $len)?;
                Self::read_body(body)
            }
            fn write(&self, out: &mut Vec<u8>) -> Result<(), $error> {
                self.write_body(out)
            }
        }
    };
    (@items [] $($name:ident),*) => {};
    (@items [$items:path] $($name:ident),*) => { $( $items!($name); )* };
    (@length $enum:ident {} $rows:tt) => {};
    (@length $enum:ident {$(#[$doc:meta])* $length:ident} [$($kind:literal => $len:literal,)*]) => {
        impl $enum {
            $(#[$doc])*
            pub fn $length(kind: u8) -> Option<usize> {
                match kind { $( $kind => Some($len), )* _ => None }
            }
        }
    };
    (@access $enum:ident {} $rows:tt) => {};
    (@access $enum:ident {
        $( $(#[$doc:meta])* $method:ident $borrow:tt -> $field:ident: $ty:ty; )*
    } $rows:tt) => {
        $( $crate::layout!(@accessor $enum $(#[$doc])* $method $borrow $field: $ty; $rows); )*
    };
    (@accessor $enum:ident $(#[$doc:meta])* $method:ident (&self) $field:ident: $ty:ty;
        [$($name:ident),*]) => {
        impl $enum {
            $(#[$doc])*
            pub fn $method(&self) -> &$ty {
                match self { $( Self::$name(m) => &m.$field, )* }
            }
        }
    };
    (@accessor $enum:ident $(#[$doc:meta])* $method:ident (&mut self) $field:ident: $ty:ty;
        [$($name:ident),*]) => {
        impl $enum {
            $(#[$doc])*
            pub fn $method(&mut self) -> &mut $ty {
                match self { $( Self::$name(m) => &mut m.$field, )* }
            }
        }
    };
}
