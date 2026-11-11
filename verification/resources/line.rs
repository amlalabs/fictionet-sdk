//! The line a costed session prints when it ends: `Costs::print` (cost.rs
//! beside this file) writes it, and the verify commands read it back
//! (`xtask/src/resources.rs`, which includes this file too). Its
//! [`Display`](fmt::Display) is the one definition of the format;
//! [`CostLine::find`] reads only what it would print.

// Each binary that includes it uses only part of it.
#![allow(dead_code)]

use core::fmt;
use std::string::String;
use std::vec::Vec;

/// What a session's steps came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CostLine {
    /// The session, as named to `Costs::new`.
    pub session: String,
    /// The steps checked.
    pub steps: usize,
    /// The step that came closest to its charge: the most bytes live at
    /// once, against the bytes charged.
    pub charge: Closest,
    /// The step that came closest to its linear bound: the bytes asked
    /// for, against the bytes allowed.
    pub linear: Closest,
}

/// How close a bound came: `used` of `allowed` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Closest {
    pub used: usize,
    pub allowed: usize,
}

/// A line that starts a cost line but is not one [`CostLine`] prints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Malformed<'a>(pub &'a str);

impl CostLine {
    /// What every cost line starts with.
    pub(crate) const PREFIX: &'static str = "cost: ";

    /// The cost line in `line`, if it has one. It may start after other
    /// output on the same line, as when tests print side by side.
    pub(crate) fn find(line: &str) -> Option<Result<Self, Malformed<'_>>> {
        let start = line.find(Self::PREFIX)?;
        let text = &line[start..];
        Some(Self::parse(text).ok_or(Malformed(text)))
    }

    /// `text` as a cost line: the session, then the five numbers in the
    /// order [`Display`](fmt::Display) prints them, and nothing it would
    /// not print.
    fn parse(text: &str) -> Option<Self> {
        let (session, counts) = text.strip_prefix(Self::PREFIX)?.rsplit_once(": ")?;
        let numbers: Vec<usize> = counts
            .split(|c: char| !c.is_ascii_digit())
            .filter(|run| !run.is_empty())
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        let [steps, used, charged, asked, allowed] = numbers[..] else {
            return None;
        };
        let line = Self {
            session: session.into(),
            steps,
            charge: Closest {
                used,
                allowed: charged,
            },
            linear: Closest {
                used: asked,
                allowed,
            },
        };
        (std::format!("{line}") == text).then_some(line)
    }
}

impl fmt::Display for CostLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}{}: {} steps within their charge and linear bound, closest {} of {} bytes \
             charged and {} of {} bytes allowed",
            Self::PREFIX,
            self.session,
            self.steps,
            self.charge.used,
            self.charge.allowed,
            self.linear.used,
            self.linear.allowed,
        )
    }
}
