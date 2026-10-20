//! `fictionet observe`: the observe API from a shell. Writes each JSON value
//! followed by a newline, so scripts can read a world without speaking the
//! observation protocol themselves. The original bytes are preserved.

use std::io::Write;

use fictionet_observe::Envelope;

use crate::args::take_observation;
use crate::config::{connect_observation, observation_path};

pub(crate) const USAGE: &str = "\
usage: fictionet observe --observation unix:<path> [<request>]

--observation names the Unix socket a world serves with fictionet_observe::serve.
Sends one request and writes each JSON reply followed by a newline. Streams
(watch, packets) run until the world ends them or you stop the command.
Binary values (pcap, keylog) are written to stdout as they are.

Requests:
  world                   the observation API version and whether the world runs
  graph                   tasks, groups, hosts, sandboxes, links and loss status (default)
  watch [<after>]         the graph, then every change, as JSON lines; with <after>,
                          first every event the collector kept after that number
  counters                packets and bytes on every link
  events [<after>]        the events the collector kept after that number (from 0), up to 1000
  link <link>             one link, such as e12
  packets <link>          a link's retained packets, then captured packets, decoded
  packet <link> <seq>     one retained packet's layers and bytes
  pcap <link>             a pcapng export of the link's retained capture
  keylog                  retained TLS keys, as an SSLKEYLOGFILE
  '{\"op\":...}'            any request, as JSON

Start packets <link> before requesting packet details or pcap. Those requests
need the link's decoded capture to remain in memory. Retention is bounded.

Exit status: 0 when the reply ended, including a watch closed between values
after its world ended, 1 if the world sent an error, could not be reached,
went away while running or truncated a reply value, 2 on bad arguments.";

/// The request for the words after the flags.
pub(crate) fn request(words: &[String]) -> Result<String, String> {
    let w: Vec<&str> = words.iter().map(String::as_str).collect();
    let link = |l: &str| format!("\"{}\"", l.replace(['"', '\\'], ""));
    Ok(match w.as_slice() {
        [] | ["graph"] => r#"{"op":"graph"}"#.into(),
        [json] if json.starts_with('{') => (*json).to_owned(),
        [op @ ("world" | "watch" | "counters" | "keylog" | "events")] => {
            format!(r#"{{"op":"{op}"}}"#)
        }
        [op @ ("watch" | "events"), after] => {
            format!(r#"{{"op":"{op}","after":{}}}"#, number(after)?)
        }
        [op @ ("link" | "packets" | "pcap"), l] => format!(r#"{{"op":"{op}","link":{}}}"#, link(l)),
        ["packet", l, seq] => format!(
            r#"{{"op":"packet","link":{},"seq":{}}}"#,
            link(l),
            number(seq)?
        ),
        _ => return Err(format!("unknown request: {}", words.join(" "))),
    })
}

fn number(s: &str) -> Result<u64, String> {
    s.parse().map_err(|_| format!("{s} is not a number"))
}

pub(crate) fn main(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return 0;
    }
    let parsed = take_observation(args).and_then(|(world, rest)| {
        let path = observation_path(&world)?;
        Ok((path, request(&rest)?))
    });
    let (path, request) = match parsed {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("fictionet observe: {msg}");
            return 2;
        }
    };
    let mut client = match connect_observation(&path) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("fictionet observe: {msg}");
            return 1;
        }
    };
    if let Err(e) = client.request(&request) {
        eprintln!("fictionet observe: {e}");
        return 1;
    }
    let stdout = std::io::stdout();
    // A world that exits right after its run ends may close the socket
    // before its stream's end: only a close between values is a normal end.
    let mut saw_ended = false;
    loop {
        let value = match client.next_value() {
            Ok(Some(v)) => v,
            Ok(None) if saw_ended => return 0,
            Ok(None) => {
                eprintln!("fictionet observe: the world closed the connection");
                return 1;
            }
            Err(e) => {
                eprintln!("fictionet observe: {e}");
                return 1;
            }
        };
        let envelope = value.envelope();
        saw_ended |= matches!(&envelope, Some(Envelope::Event { name, .. }) if name == "ended");
        let mut out = stdout.lock();
        let written = if value.binary {
            out.write_all(&value.bytes)
        } else {
            out.write_all(&value.bytes)
                .and_then(|()| out.write_all(b"\n"))
        };
        if let Err(e) = written.and_then(|()| out.flush()) {
            // stdout closed, such as a pipe into head: stop quietly. Any
            // other error, such as a full disk, is a failure.
            if e.kind() == std::io::ErrorKind::BrokenPipe {
                return 0;
            }
            eprintln!("fictionet observe: writing to stdout: {e}");
            return 1;
        }
        if value.end {
            return if matches!(envelope, Some(Envelope::Error(_))) {
                1
            } else {
                0
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(s: &str) -> Vec<String> {
        s.split_whitespace().map(str::to_owned).collect()
    }

    #[test]
    fn requests_from_words() {
        assert_eq!(request(&[]).unwrap(), r#"{"op":"graph"}"#);
        assert_eq!(request(&words("watch")).unwrap(), r#"{"op":"watch"}"#);
        assert_eq!(
            request(&words("packets e12")).unwrap(),
            r#"{"op":"packets","link":"e12"}"#
        );
        assert_eq!(
            request(&words("packet e12 40")).unwrap(),
            r#"{"op":"packet","link":"e12","seq":40}"#
        );
        assert_eq!(
            request(&words("events 7")).unwrap(),
            r#"{"op":"events","after":7}"#
        );
        assert_eq!(
            request(&words("watch 0")).unwrap(),
            r#"{"op":"watch","after":0}"#
        );
        assert!(request(&words("packet e12 x")).is_err());
        assert!(request(&words("fly")).is_err());
    }
}
