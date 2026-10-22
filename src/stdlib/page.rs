//! A page's own typed state, streamed as server-sent JSON snapshots.
//!
//! The world owns its state and chooses when to publish it. Each browser
//! receives the current value on connection, then the latest value after
//! each change. Slow readers coalesce updates. Closing the sender ends the
//! stream. No run, events, packet capture, or page description is involved.
//!
//! Compose the route with your HTML, assets, commands, and access rules:
//!
//! ```no_run
//! use axum::{Router, response::Html, routing::get};
//! use fictionet::stdlib::page;
//! use serde::Serialize;
//!
//! #[derive(Clone, Serialize)]
//! struct State { requests: usize }
//!
//! # async fn serve() -> Result<(), Box<dyn std::error::Error>> {
//! let (state, snapshots) = tokio::sync::watch::channel(State { requests: 0 });
//! let app = Router::new()
//!     .route("/", get(|| async { Html("<h1>My world</h1>") }))
//!     .merge(page::state(snapshots));
//! state.send_replace(State { requests: 1 });
//! let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
//! axum::serve(listener, app).await?;
//! # Ok(()) }
//! ```
//!
//! A browser can read `/state` with `EventSource`. The socket components
//! below are independent JavaScript modules a page may serve or copy.

use axum::Router;
use axum::response::Sse;
use axum::response::sse::Event;
use axum::routing::get;
use serde::Serialize;
use tokio::sync::watch;
use tokio_stream::{StreamExt, wrappers::WatchStream};

/// A ghostty-web terminal component. Its caller supplies the library and socket.
pub const TERMINAL: &str = include_str!("page/terminal.mjs");
/// A noVNC screen component. Its caller supplies the library and socket.
pub const SCREEN: &str = include_str!("page/screen.mjs");

/// Serves one concrete state type at `GET /state`.
///
/// Serialization errors terminate that client's stream. The sender and the
/// application decide state size, publication rate, and who can read it.
pub fn state<T>(snapshots: watch::Receiver<T>) -> Router
where
    T: Clone + Serialize + Send + Sync + 'static,
{
    Router::new().route(
        "/state",
        get(move || {
            let snapshots = snapshots.clone();
            async move {
                Sse::new(WatchStream::new(snapshots).map(|state| Event::default().json_data(state)))
            }
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http::Request;
    use http_body_util::BodyExt;
    use tower_service::Service;

    #[derive(Clone, Serialize)]
    struct Counts {
        requests: usize,
    }

    #[tokio::test]
    async fn snapshots_start_current_coalesce_and_end_with_the_sender() {
        let (updates, snapshots) = watch::channel(Counts { requests: 0 });
        let mut app = state(snapshots);
        updates.send_replace(Counts { requests: 1 });
        let response = app
            .call(Request::get("/state").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        let mut body = response.into_body();
        let first = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(first, "data: {\"requests\":1}\n\n");
        updates.send_replace(Counts { requests: 2 });
        updates.send_replace(Counts { requests: 3 });
        let latest = body.frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(latest, "data: {\"requests\":3}\n\n");
        drop(updates);
        assert!(body.frame().await.is_none());
    }

    #[tokio::test]
    async fn dropping_a_client_releases_its_subscription() {
        let (updates, snapshots) = watch::channel(Counts { requests: 0 });
        let mut app = state(snapshots);
        let response = app
            .call(Request::get("/state").body(Body::empty()).unwrap())
            .await
            .unwrap();
        drop(app);
        assert_eq!(updates.receiver_count(), 1);
        drop(response);
        assert_eq!(updates.receiver_count(), 0);
    }
}
