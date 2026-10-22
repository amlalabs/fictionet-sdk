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

mod dom;
pub mod models;
pub mod search;
pub mod sites;
mod text;

pub mod capture;
pub mod crawl;
pub mod warc;
