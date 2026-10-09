//! Concrete service fixtures with explicit callback arguments.

macro_rules! service_fixture {
    ($service:ty => ($decoder:ty, $state:ty, $error:ty);
     decoder($this:ident) $decode:block
     $($method:ident($receiver:ident $(, $arg:tt: $arg_ty:ty)*;
                    $state_arg:pat_param, $driver:pat_param) -> $result:ty $body:block)*) => {
        impl fictionet::stdlib::serve::Service for $service {
            type Decoder = $decoder;
            type State = $state;
            type Error = $error;
            fn decoder(&$this) -> Self::Decoder $decode
            $(fn $method(
                &mut $receiver,
                $($arg: $arg_ty,)*
                $state_arg: &Self::State,
                $driver: &mut fictionet::stdlib::serve::Driver<'_, Self::Decoder>,
            ) -> core::result::Result<$result, Self::Error> $body)*
        }
    };
}
