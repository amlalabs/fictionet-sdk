//! Generate a protocol once, then own and edit the resulting Rust file.
//!
//! Front ends parse bounded inputs into [`Schema`]. [`validate`] resolves
//! names and limits. [`emit`] accepts only a [`ValidatedSchema`]. The crate
//! uses only the standard library and performs no network access.
//!
//! ```
//! use fictionet_codegen::{FrontEnd, IrFrontEnd, Input, Limits, validate, emit};
//! let input = Input { name: "empty.json".into(), bytes: br#"{"types":[]}"#.to_vec() };
//! let schema = IrFrontEnd.parse(&[input], Limits::default())?;
//! let checked = validate(schema, Limits::default())?;
//! let source = emit(&checked, &["empty.json".into()])?;
//! assert!(source.contains("copy and edit"));
//! # Ok::<(), fictionet_codegen::Error>(())
//! ```
mod emit;
mod frontend;
pub mod ir;
mod json;
mod validate;
pub use emit::{emit, emit_fuzz};
pub use frontend::{FORMATS, FrontEnd, Generated, Input, IrFrontEnd, generate};
pub use ir::*;
pub use validate::{IdentifierCase, ValidatedSchema, rust_identifier, validate};

/// A stable category for generator failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    /// A source, JSON tree, or generated file exceeds a named limit.
    InputLimit,
    /// Invalid JSON syntax, including duplicate object keys.
    JsonSyntax,
    /// JSON has an unexpected member, type, or missing required member.
    JsonShape,
    /// No front end has this name.
    UnknownFormat,
    /// Invalid CLI arguments.
    Cli,
    /// Local file or standard stream I/O failed.
    Io,
    /// A source name occurs twice in one scope.
    DuplicateName,
    /// A name is empty, too long, or contains no ASCII letter or digit.
    InvalidName,
    /// Names collide after Rust mapping, or with generated names.
    RustCollision,
    /// A fixed wire size disagrees with the type.
    InvalidSize,
    /// A discriminant, null, or bit does not fit, or is duplicated.
    InvalidValue,
    /// A named reference does not resolve.
    UnknownReference,
    /// The schema exceeds a structural limit.
    IrLimit,
    /// A requested resource limit is outside its supported range.
    InvalidLimit,
    /// A mandatory reference cycle has no finite value.
    UninhabitedType,
}

/// A typed failure with a source location or schema path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Error {
    /// Stable failure category.
    pub kind: ErrorKind,
    /// Input position, option name, or schema path.
    pub location: String,
    /// Short explanation.
    pub message: String,
}
impl Error {
    pub(crate) fn new(
        kind: ErrorKind,
        location: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            location: location.into(),
            message: message.into(),
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {:?}: {}", self.location, self.kind, self.message)
    }
}
impl std::error::Error for Error {}
