//! The generator's goldens, each compiled as a module a user copies in.
// A golden emits every helper its schema could need, and not every schema
// uses them all.
#![allow(dead_code)]

pub mod blocks;
pub mod budgets;
pub mod edges;
pub mod float_nulls;
pub mod groups;
pub mod long_names;
pub mod one_field;
pub mod primitives;
pub mod recursive;
pub mod sbe_sample;
pub mod short_names;
pub mod xdr;
