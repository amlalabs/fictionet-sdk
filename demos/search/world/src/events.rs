//! The request log, written from the events of everything the network
//! does: one line per DNS query, decision about a name, certificate,
//! failed TLS handshake and HTTP request.
//!
//! The handler ([`handler`](crate::handler)) puts what the pages said
//! about a page (generated or cached, the model, the time it took, its
//! claims) in its response's extensions. The `http.request` event brings
//! them back here, so one `http` line holds both what the agent asked for
//! and what it was shown. `bytes` keeps the handler's declared body length;
//! `sent` and `complete` record the HTTP service's actual delivery. A HEAD
//! request can finish without sending the declared body.

use std::sync::Arc;

use fictionet::events::Event;
use fictionet::stdlib::protocols::json::Value as J;
use serde_json::{Map, Value, json};

use fictionet_extras::events::js;
use fictionet_extras::log::Log;

use fictionet_extras::headers;

/// Projects run events into the world's JSON Lines format.
pub struct LogObserver {
    pub log: Arc<Log>,
}

impl fictionet::events::Observer for LogObserver {
    fn enabled(&self, interest: fictionet::events::Interest<'_>) -> bool {
        let fictionet::events::Interest::Event(metadata, _) = interest else {
            return false;
        };
        matches!(metadata.source, "net" | "dns" | "tls" | "http" | "web")
    }
    fn lost(&self, loss: fictionet::events::Loss) {
        if loss.stream != fictionet::events::Stream::Events {
            return;
        }
        let count = loss.count;
        if count != 0 {
            self.log
                .write(serde_json::json!({"type": "lost", "count": count}));
            self.log
                .fail(format!("{count} events lost before log delivery"));
        }
    }
    fn observe(
        &self,
        _: fictionet::events::Stamp,
        observation: fictionet::events::Observation<'_>,
    ) {
        if let fictionet::events::Observation::Event(event) = observation
            && let Some(line) = line(event)
        {
            self.log.write(line);
        }
    }
}

/// Page fields an `http` line keeps, in this order. None is a name
/// `http.request` uses itself. There, `query` is the URL query, so search
/// text is `search`. The search projection also reads `listed` and
/// `reason`, which the line leaves out.
const PAGE_FIELDS: [&str; 19] = [
    "kind",
    "cache",
    "engine",
    "search",
    "results",
    "title",
    "model",
    "gen_ms",
    "cost",
    "serve_ms",
    "prefetched",
    "claims",
    "mentions",
    "unsupported_snippets",
    "unchecked_snippets",
    "tells",
    "location",
    "error",
    "bytes",
];

fn get(e: &Event, name: &str) -> Value {
    js(e.get(name))
}

/// The log line for `e`, if it is one the log keeps.
fn line(e: &Event) -> Option<Value> {
    let name = e.conn.sandbox.as_ref().map(|s| s.name.clone());
    match (e.source, e.kind) {
        ("web", "real_search") => Some(
            json!({"type":"real_search", "search": get(e, "search"), "engine": get(e, "engine"), "start": get(e, "start")}),
        ),
        ("web", "downloaded" | "copy_served" | "download_failed") => Some(
            json!({"type":e.kind, "url":get(e, "url"), "status":get(e, "status"), "elapsed_ms":get(e, "elapsed_ms")}),
        ),
        ("web", "model_call") => {
            let mut call = get(e, "call");
            call["type"] = json!("model_call");
            Some(call)
        }
        ("web", "search") => Some(json!({"type":"search", "id":get(e,"query_id"),
            "source":get(e,"source"), "query":get(e,"search"),
            "results":e.str("returned").and_then(|s| serde_json::from_str::<Value>(s).ok()).unwrap_or(Value::Null)})),
        ("web", "generation") => Some(json!({"type": "generation",
            "generate": get(e, "generate"), "revision": get(e, "revision")})),
        ("web", "query") => Some(json!({"type": "query", "id": get(e, "query_id"),
            "engine": get(e, "engine"), "search": get(e, "search"), "start": get(e, "start")})),
        ("web", "search_answer") => {
            let mut row = json!({"type": "search_answer",
                "id": get(e, "query_id"), "cache": get(e, "cache"), "results": get(e, "results"),
                "model": get(e, "model")});
            for name in ["gen_ms", "serve_ms", "cost"] {
                if let Some(value) = e.get(name) {
                    row[name] = js(Some(value));
                }
            }
            Some(row)
        }
        ("web", "query_failed") => {
            let mut line =
                json!({"type": "query_failed", "id": get(e, "query_id"), "why": get(e, "why")});
            for name in ["error", "serve_ms"] {
                if let Some(value) = e.get(name) {
                    line[name] = js(Some(value));
                }
            }
            Some(line)
        }
        ("net", "attached") => {
            println!("attached {}", name.as_deref().unwrap_or(""));
            None
        }
        ("net", "detached") => {
            println!("detached {}", name.as_deref().unwrap_or(""));
            None
        }
        ("web", "site") => Some(json!({
            "type": "site",
            "host": get(e, "host"),
            "addr": get(e, "addr"),
            "why": get(e, "why"),
        })),
        ("web", "refused") => {
            Some(json!({"type": "refused", "host": get(e, "host"), "why": get(e, "why")}))
        }
        ("web", "cert") => Some(json!({
            "type": "cert",
            "host": get(e, "host"),
            "not_before": get(e, "not_before"),
            "not_after": get(e, "not_after"),
        })),
        ("dns", "query") => Some(json!({
            "type": "dns",
            "via": if e.get("tcp").and_then(J::as_bool) == Some(true) { "tcp" } else { "udp" },
            "name": get(e, "name"),
            "qtype": get(e, "qtype"),
            "answer": get(e, "answer"),
            "addr": get(e, "addr"),
        })),
        ("tls", "handshake") => tls(e),
        ("http", "request") => Some(http(e)),
        _ => None,
    }
}

/// A TLS handshake that did not finish: `tls_reject` when the world refused
/// the name, `tls_error` when the client gave up or broke the protocol.
fn tls(e: &Event) -> Option<Value> {
    let sni = get(e, "sni");
    let error = match e.str("outcome")? {
        "accepted" => return None,
        "rejected" => return Some(json!({"type": "tls_reject", "sni": sni})),
        "alert" => format!("the client sent alert {}", e.u64("alert_code").unwrap_or(0)),
        "failed" => e
            .str("detail")
            .unwrap_or_default()
            .chars()
            .take(200)
            .collect(),
        "closed" => "the client closed the connection before the handshake finished".to_owned(),
        "timed_out" => "the handshake did not finish within 10 seconds".to_owned(),
        _ => "the handshake failed".to_owned(),
    };
    Some(json!({"type": "tls_error", "sni": sni, "error": error}))
}

/// An HTTP request: what the agent asked for, then what the world made of
/// it.
fn http(e: &Event) -> Value {
    let path = match e.str("query") {
        Some(q) => format!("{}?{q}", e.str("path").unwrap_or("/")),
        None => e.str("path").unwrap_or("/").to_owned(),
    };
    let mut line = Map::new();
    line.insert("type".into(), json!("http"));
    line.insert("scheme".into(), get(e, "scheme"));
    line.insert("method".into(), get(e, "method"));
    line.insert("host".into(), get(e, "host"));
    line.insert("path".into(), json!(path));
    line.insert("ua".into(), json!(headers::header(e, "user-agent")));
    line.insert("referer".into(), json!(headers::header(e, "referer")));
    line.insert("answer".into(), get(e, "answer"));
    line.insert("status".into(), get(e, "status"));
    line.insert("sent".into(), get(e, "sent"));
    line.insert("complete".into(), get(e, "complete"));
    for name in PAGE_FIELDS {
        if let Some(v) = e.get(name) {
            line.insert(name.into(), js(Some(v)));
        }
    }
    if !line.contains_key("bytes") {
        line.insert("bytes".into(), get(e, "sent"));
    }
    Value::Object(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_commands_emit_only_changes() {
        use crate::pages::{Applied, Command, Generation, Pages, Rejected, Seed};
        use crate::search::Searches;
        use fictionet::events::Fanout;
        use fictionet_observe::Memory;

        let pages = Pages::new(Seed::builtin("web").unwrap());
        let searches = Arc::new(Searches::of(&pages));
        let memory = Arc::new(Memory::default());
        let initial = searches.snapshot();
        assert!(initial.generator.generate);
        assert_eq!(initial.generator.generation_revision, 0);
        assert_eq!(initial.revision, 0);
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)).observer(Arc::new(
                Fanout::new(vec![memory.clone(), searches.clone()]),
            )),
            |cx| async move {
                assert_eq!(
                    pages.generation(),
                    Generation {
                        generate: true,
                        revision: 0
                    }
                );
                let set = |generate, expected_revision| {
                    let value = json!({"command":"set_generation","generate":generate,
                        "expected_revision":expected_revision});
                    let command: Command = serde_json::from_value(value.clone()).unwrap();
                    assert_eq!(serde_json::to_value(&command).unwrap(), value);
                    pages.apply(&cx, command)
                };
                assert_eq!(set(false, 1), Err(Rejected::Stale { current: 0 }));
                assert_eq!(
                    pages.generation(),
                    Generation {
                        generate: true,
                        revision: 0
                    }
                );
                assert_eq!(
                    set(true, 0),
                    Ok(Applied {
                        revision: 0,
                        at_ms: 0
                    })
                );
                let applied = set(false, 0).unwrap();
                assert_eq!(
                    applied,
                    Applied {
                        revision: 1,
                        at_ms: 0
                    }
                );
                assert_eq!(
                    serde_json::to_value(applied).unwrap(),
                    json!({"revision":1,"at_ms":0})
                );
                assert_eq!(set(false, 1), Ok(applied));
                assert_eq!(set(true, 0), Err(Rejected::Stale { current: 1 }));
                assert_eq!(set(false, 0), Err(Rejected::Stale { current: 1 }));
                assert_eq!(
                    pages.generation(),
                    Generation {
                        generate: false,
                        revision: 1
                    }
                );
                let rejected = serde_json::to_value(Rejected::Stale { current: 1 }).unwrap();
                assert_eq!(rejected, json!({"reason":"stale","current":1}));
                assert_eq!(
                    serde_json::from_value::<Rejected>(rejected).unwrap(),
                    Rejected::Stale { current: 1 }
                );
                Ok(())
            },
        ))
        .unwrap();
        let all = memory.checked_all().unwrap();
        let (start, events) = all.split_first().unwrap();
        assert_eq!((start.source, start.kind), ("run", "start"));
        assert_eq!(events.len(), 1);
        assert_eq!((events[0].source, events[0].kind), ("web", "generation"));
        assert_eq!(
            line(&events[0]),
            Some(json!({"type":"generation","generate":false,"revision":1}))
        );
        let state = searches.snapshot();
        assert!(!state.generator.generate);
        assert_eq!(state.generator.generation_revision, 1);
        assert_eq!(state.revision, 1);
        assert_eq!(state.at_ms, 0);
        assert_eq!(
            serde_json::from_value::<crate::search::Snapshot>(
                serde_json::to_value(&state).unwrap()
            )
            .unwrap(),
            state
        );
    }

    #[test]
    fn query_lines_and_http_context() {
        use fictionet::events::{Fanout, Observation, Observer, Stamp, Stream};
        use fictionet_observe::Memory;
        let query = Event::new("web", "query")
            .field("query_id", 3u64)
            .field("engine", "google")
            .field("search", "a")
            .field("start", 10u64);
        assert_eq!(
            line(&query),
            Some(json!({"type":"query","id":3,"engine":"google","search":"a","start":10}))
        );
        for why in ["error", "budget", "abandoned"] {
            let failed = Event::new("web", "query_failed")
                .field("query_id", 3u64)
                .field("why", why);
            assert_eq!(
                line(&failed),
                Some(json!({"type":"query_failed","id":3,"why":why}))
            );
            let failed = failed.field("error", "stopped").field("serve_ms", 7u64);
            assert_eq!(
                line(&failed),
                Some(
                    json!({"type":"query_failed","id":3,"why":why,"error":"stopped","serve_ms":7})
                )
            );
        }
        let memory = Arc::new(Memory::default());
        let observer = Fanout::new(vec![memory.clone()]);
        let event = Event::new("http", "request")
            .field("path", "/search")
            .field("query", "q=a")
            .field("query_id", 3u64)
            .field("listed", J::Array(vec![]))
            .field("reason", "direct");
        let stamp = Stamp {
            stream: Stream::Events,
            seq: 1,
            at: fictionet::time::Instant::ZERO,
        };
        observer.observe(stamp, Observation::Event(&event));
        let events = memory.checked_of("http", "request").unwrap();
        assert_eq!(events[0].u64("query_id"), Some(3));
        assert_eq!(events[0].str("query"), Some("q=a"));
        assert_eq!(events[0].fields, event.fields);
        assert_eq!(line(&events[0]), line(&event));
        let http = line(&events[0]).unwrap();
        assert_eq!(http["path"], "/search?q=a");
        for name in ["query", "query_id", "listed", "reason"] {
            assert!(http.get(name).is_none());
        }
    }

    #[test]
    fn producer_loss_prevents_successful_finalization() {
        let log = Arc::new(Log::new(Box::new(std::io::sink()), &[], |text| text));
        let observer = LogObserver { log: log.clone() };
        fictionet::block_on(fictionet::lab(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(1)),
            |cx| {
                log.attach(&cx);
                fictionet::events::Observer::lost(
                    &observer,
                    fictionet::events::Loss::staged(fictionet::events::Stream::Events, 3),
                );
                async { Ok(()) }
            },
        ))
        .unwrap();
        assert_eq!(
            log.finish().unwrap_err().to_string(),
            "3 events lost before log delivery"
        );
    }

    #[test]
    fn delivery_is_separate_from_declared_length() {
        for (method, sent, complete) in
            [("HEAD", 0u64, true), ("GET", 20, false), ("GET", 100, true)]
        {
            let event = Event::new("http", "request")
                .field("method", method)
                .field("status", 200u64)
                .field("bytes", 100u64)
                .field("sent", sent)
                .field("complete", complete);
            let line = line(&event).unwrap();
            assert_eq!(line["method"], method);
            assert_eq!(line["bytes"], 100);
            assert_eq!(line["sent"], sent);
            assert_eq!(line["complete"], complete);
        }
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;

    #[test]
    fn model_calls_keep_cost_time_and_outcome_in_the_run_log() {
        let call = json!({"record":"attempt", "kind":"page", "url":"https://example.com/a",
            "model":"writer", "cost":0.001, "gen_ms":3200, "outcome":"ok", "terminal":true});
        let event =
            Event::new("web", "model_call").field("call", fictionet_extras::events::field(&call));
        let mut expected = call;
        expected["type"] = json!("model_call");
        assert_eq!(line(&event), Some(expected));
        let event = Event::new("web", "search_answer")
            .field("gen_ms", 3800u64)
            .field("serve_ms", 3800u64)
            .field("cost", fictionet::events::float(0.002));
        let row = line(&event).unwrap();
        assert_eq!(row["gen_ms"], 3800);
        assert_eq!(row["serve_ms"], 3800);
        assert_eq!(row["cost"], 0.002);
    }
}
