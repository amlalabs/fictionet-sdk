use std::fmt::{self, Debug, Display};
use std::ops::Deref;
use std::sync::Arc;

/// Any error a world returns: one failure, which the [region](crate::Cx#regions)
/// that keeps it and a [`Task::join`](crate::Task::join) that asks for it
/// share.
///
/// Any error type that implements [`std::error::Error`], `Send` and `Sync`
/// converts into it with `?` or `.into()`. A message becomes one with
/// [`Error::msg`]:
///
/// ```
/// # fn check(n: usize) -> fictionet::Result {
/// if n > 3 {
///     return Err(fictionet::Error::msg(format!("{n} is too many")));
/// }
/// let port: u16 = "8080".parse()?;
/// # let _ = port;
/// # Ok(())
/// # }
/// ```
///
/// It dereferences to the error inside, so `e.is::<T>()`,
/// `e.downcast_ref::<T>()` and `e.source()` reach the original error:
///
/// ```
/// let e: fictionet::Error = fictionet::Cancelled.into();
/// assert!(e.is::<fictionet::Cancelled>());
/// ```
///
/// Cloning it is a reference count, not a copy of the error. It does not
/// implement [`std::error::Error`] itself, as `anyhow::Error` does not,
/// because then `From` could not take every error type. For code that
/// wants a `Box<dyn Error + Send + Sync>`, it converts into one; the box
/// holds this handle, and its [`source`](std::error::Error::source) is the
/// error inside.
#[derive(Clone)]
pub struct Error(Arc<dyn std::error::Error + Send + Sync + 'static>);

impl Error {
    /// A message as an error.
    pub fn msg<M: Display + Debug + Send + Sync + 'static>(message: M) -> Error {
        Error(Arc::new(Message(message)))
    }

    /// A boxed error as an `Error`. `?` cannot do this one, because a
    /// `Box<dyn Error>` does not implement [`std::error::Error`] itself.
    pub fn boxed(error: Box<dyn std::error::Error + Send + Sync + 'static>) -> Error {
        Error(Arc::from(error))
    }
}

impl<E: std::error::Error + Send + Sync + 'static> From<E> for Error {
    fn from(error: E) -> Error {
        Error(Arc::new(error))
    }
}

impl Deref for Error {
    type Target = dyn std::error::Error + Send + Sync + 'static;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl AsRef<dyn std::error::Error + Send + Sync + 'static> for Error {
    fn as_ref(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        &*self.0
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&*self.0, f)
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&*self.0, f)
    }
}

impl From<Error> for Box<dyn std::error::Error + Send + Sync + 'static> {
    fn from(error: Error) -> Self {
        Box::new(Shared(error))
    }
}

/// An error and every [`source`](std::error::Error::source) under it, on
/// one line: `the service failed: IMAP framing failed: line too long`.
///
/// An error's own text names only its own context, and the error it wraps
/// comes through `source`, so a log or a screen that shows an error shows
/// it this way.
///
/// ```
/// let e = fictionet::JoinError::Failed(fictionet::Error::msg("bad"));
/// assert_eq!(e.to_string(), "the task failed");
/// assert_eq!(fictionet::ErrorChain(&e).to_string(), "the task failed: bad");
/// ```
#[derive(Clone, Copy)]
pub struct ErrorChain<'a>(pub &'a (dyn std::error::Error + 'static));

impl Display for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for e in std::iter::successors(Some(self.0), |e| e.source()) {
            if !first {
                f.write_str(": ")?;
            }
            first = false;
            Display::fmt(e, f)?;
        }
        Ok(())
    }
}

impl Debug for ErrorChain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

/// An [`Error`] as a [`std::error::Error`], for its conversion into a
/// `Box<dyn Error>`. It says what the error inside says, and gives it as
/// its source.
struct Shared(Error);

impl Display for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl Debug for Shared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl std::error::Error for Shared {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&*self.0.0)
    }
}

/// The error [`Error::msg`] makes.
struct Message<M>(M);

impl<M: Display> Display for Message<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

impl<M: Debug> Debug for Message<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Debug::fmt(&self.0, f)
    }
}

impl<M: Display + Debug> std::error::Error for Message<M> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Outer(std::io::Error);
    impl Display for Outer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("outer")
        }
    }
    impl std::error::Error for Outer {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn a_clone_is_the_same_error() {
        let e: Error = Outer(std::io::Error::other("inner")).into();
        let c = e.clone();
        assert!(std::ptr::addr_eq(&*e, &*c));
        assert!(c.is::<Outer>());
        assert_eq!(c.source().unwrap().to_string(), "inner");
    }

    #[test]
    fn messages_and_boxes_convert() {
        assert_eq!(Error::msg("text").to_string(), "text");
        assert_eq!(format!("{:?}", Error::msg("text")), "\"text\"");
        let boxed: Box<dyn std::error::Error + Send + Sync> = "boxed".into();
        assert_eq!(Error::boxed(boxed).to_string(), "boxed");
        let back: Box<dyn std::error::Error + Send + Sync> = Error::from(crate::Cancelled).into();
        assert_eq!(back.to_string(), crate::Cancelled.to_string());
        assert!(back.source().unwrap().is::<crate::Cancelled>());
    }
}
