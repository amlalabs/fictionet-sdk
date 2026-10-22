//! Optional components for worlds.
//!
//! [`search`] renders search engines; [`sites`] supplies reusable site skins and
//! their local assets. Neither module performs network requests.
//! [`models`] serves provider APIs through the standard library's host client.
//!
//! ```
//! use fictionet_extras::{search, sites};
//! use time::{Date, Month};
//!
//! let results = search::Search {
//!     results: vec![search::Result {
//!         title: "Iterator tools".into(),
//!         url: "https://docs.python.org/3/library/itertools.html".into(),
//!         snippet: "Tools for combining iterators.".into(),
//!         ..Default::default()
//!     }],
//!     ..Default::default()
//! };
//! let html = search::render(search::Engine::Google, "iterator tools", &results, 0);
//! assert!(html.contains("Iterator tools"));
//!
//! let skin = sites::lookup("docs.python.org", "/3/library/itertools.html").unwrap();
//! let today = Date::from_calendar_date(2026, Month::October, 7).unwrap();
//! let page = skin.render("Iterator tools", "<h2>Usage</h2><p>Combine values.</p>", today, today).unwrap();
//! assert!(page.contains("#section-1"));
//! // Serve search::CSS at /search.css and sites::asset at /_assets/ paths.
//! ```
#![warn(missing_docs)]

pub mod args;
pub mod hyper_io;
pub mod log;

#[cfg(not(target_arch = "wasm32"))]
mod dom;

#[cfg(not(target_arch = "wasm32"))]
pub mod models;

#[cfg(not(target_arch = "wasm32"))]
pub mod search;

#[cfg(not(target_arch = "wasm32"))]
pub mod sites;

#[cfg(not(target_arch = "wasm32"))]
mod text;

#[cfg(not(target_arch = "wasm32"))]
pub mod capture;

#[cfg(not(target_arch = "wasm32"))]
pub mod crawl;

#[cfg(not(target_arch = "wasm32"))]
pub mod warc;

#[cfg(not(target_arch = "wasm32"))]
pub mod guest_content;

#[cfg(not(target_arch = "wasm32"))]
pub mod web_world;

#[cfg(not(target_arch = "wasm32"))]
pub mod zscaler;
