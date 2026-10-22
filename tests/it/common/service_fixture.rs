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
