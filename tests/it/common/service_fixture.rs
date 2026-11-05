//! Concrete service fixtures with explicit callback arguments.

macro_rules! service_fixture {
    (@timer) => { () };
    (@timer $timer:ty) => { $timer };
    ($service:ty => ($decoder:ty, $state:ty, $error:ty);
     $(timer($timer:ty);)?
     decoder($this:ident) $decode:block
     $($method:ident($receiver:ident $(, $arg:tt: $arg_ty:ty)*;
                    $state_arg:pat_param, $driver:pat_param) -> $result:ty $body:block)*) => {
        impl fictionet::stdlib::services::serve::Service for $service {
            type Timer = service_fixture!(@timer $($timer)?);
            type Decoder = $decoder;
            type State = $state;
            type Error = $error;
            fn decoder(&$this) -> Self::Decoder $decode
            $(fn $method(
                &mut $receiver,
                $($arg: $arg_ty,)*
                $state_arg: &Self::State,
                $driver: &mut fictionet::stdlib::services::serve::Driver<'_, Self::Decoder, Self::Timer>,
            ) -> core::result::Result<$result, Self::Error> $body)*
        }
    };
}

/// The same for a datagram service. `on_item` and `on_fail` take the
/// datagram's driver; every other call takes the socket's context.
macro_rules! datagram_fixture {
    (@timer) => { () };
    (@timer $timer:ty) => { $timer };
    (@context on_item) => {
        fictionet::stdlib::services::serve::DatagramDriver<'_, Self::Decoder, Self::Timer>
    };
    (@context on_fail) => {
        fictionet::stdlib::services::serve::DatagramDriver<'_, Self::Decoder, Self::Timer>
    };
    (@context $method:ident) => {
        fictionet::stdlib::services::serve::DatagramContext<'_, Self::Timer>
    };
    ($service:ty => ($decoder:ty, $state:ty, $error:ty);
     $(timer($timer:ty);)?
     decoder($this:ident) $decode:block
     $($method:ident($receiver:ident $(, $arg:tt: $arg_ty:ty)*;
                    $state_arg:pat_param, $driver:pat_param) -> $result:ty $body:block)*) => {
        impl fictionet::stdlib::services::serve::DatagramService for $service {
            type Timer = datagram_fixture!(@timer $($timer)?);
            type Decoder = $decoder;
            type State = $state;
            type Error = $error;
            fn decoder(&$this) -> Self::Decoder $decode
            $(fn $method(
                &mut $receiver,
                $($arg: $arg_ty,)*
                $state_arg: &Self::State,
                $driver: &mut datagram_fixture!(@context $method),
            ) -> core::result::Result<$result, Self::Error> $body)*
        }
    };
}
