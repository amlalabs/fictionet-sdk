//! Protocol layers: one way to stack any protocol on any carrier that has
//! the semantics it needs.
//!
//! This module starts with the connection's [`Budget`], which every layer
//! charges before it grows.

mod budget;

pub use budget::{Budget, Charge};
