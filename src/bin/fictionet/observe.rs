//! `fictionet observe`: the observe API from a shell. Prints each value the
//! world sends as one line of JSON, so scripts can read a world without
//! speaking the relay protocol themselves.

use std::io::Write;

use fictionet::relay::observer::Client;

pub(crate) const USAGE: &str = "\
usage: fictionet observe --world unix:<path> [<request>]

Connects to a world socket as an observer, sends one request, and prints
each value of the reply as one line of JSON. Streams (watch, packets) run
until the world ends them or you stop the command. Binary values (pcap,
keylog) are written to stdout as they are.

Requests:
  world                   the world's API version and whether it runs
  graph                   the tasks, sandboxes and links, with counters (the default)
  watch [<after>]         the graph, then every change, as JSON lines; with <after>,
                          first every event the world kept after that number
  counters                packets and bytes on every link
  events [<after>]        the events the world kept after that number (from 0), up to 1000
  link <link>             one link, such as e12
  packets <link>          a link's packets as they cross it, decoded
  packet <link> <seq>     one packet's layers and bytes (while the link is watched)
  pcap <link>             a pcapng capture of the link (while it is watched)
  keylog                  the world's TLS keys, as an SSLKEYLOGFILE
  '{\"op\":...}'            any request, as JSON

Exit status: 0 when the reply ended, including a watch whose world ended,
1 if the world sent an error, could not be reached or went away while
running, 2 on bad arguments.";

/// The request for the words after the flags.
pub(crate) fn request(words: &[String]) -> Result<String, String> {
    let w: Vec<&str> = words.iter().map(String::as_str).collect();
    let link = |l: &str| format!("\"{}\"", l.replace(['"', '\\'], ""));
    Ok(match w.as_slice() {
        [] | ["graph"] => r#"{"op":"graph"}"#.into(),
        [json] if json.starts_with('{') => (*json).to_owned(),
        [op @ ("world" | "watch" | "counters" | "keylog" | "events")] => format!(r#"{{"op":"{op}"}}"#),
        [op @ ("watch" | "events"), after] => format!(r#"{{"op":"{op}","after":{}}}"#, number(after)?),
        [op @ ("link" | "packets" | "pcap"), l] => format!(r#"{{"op":"{op}","link":{}}}"#, link(l)),
        ["packet", l, seq] => format!(r#"{{"op":"packet","link":{},"seq":{}}}"#, link(l), number(seq)?),
        _ => return Err(format!("unknown request: {}", words.join(" "))),
    })
}

fn number(s: &str) -> Result<u64, String> {
    s.parse().map_err(|_| format!("{s} is not a number"))
}

/// The socket path in `--world unix:<path>`, parsed as a
/// [`WorldSocket`](fictionet::WorldSocket).
pub(crate) fn world_path(world: &str) -> Result<String, String> {
    match world.parse::<fictionet::WorldSocket>() {
        Ok(fictionet::WorldSocket::UnixSocket(path)) => {
            path.into_os_string().into_string().map_err(|p| format!("--world: {} is not UTF-8", p.display()))
        }
        Ok(other) => Err(format!("--world {other} is not supported here; use unix:<path>")),
        Err(e) => Err(format!("--world: {e}")),
    }
}

/// Splits `--world <w>` (or `--world=<w>`) from the other words.
pub(crate) fn take_world(args: &[String]) -> Result<(String, Vec<String>), String> {
    let mut world = None;
    let mut rest = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--world" {
            world = Some(it.next().ok_or("--world needs a value")?.clone());
        } else if let Some(w) = a.strip_prefix("--world=") {
            world = Some(w.to_owned());
        } else {
            rest.push(a.clone());
        }
    }
    Ok((world.ok_or("--world unix:<path> is required")?, rest))
}

pub(crate) fn main(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return 0;
    }
    let parsed = take_world(args).and_then(|(world, rest)| {
        let path = world_path(&world)?;
        Ok((path, request(&rest)?))
    });
    let (path, request) = match parsed {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("fictionet observe: {msg}");
            return 2;
        }
    };
    let mut client = match Client::connect(&path, "fictionet observe") {
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
    // before its stream's end: that is still a normal end.
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
        saw_ended |= !value.binary && value.bytes.starts_with(br#"{"event":"ended","#);
        let mut out = stdout.lock();
        let written = if value.binary {
            out.write_all(&value.bytes)
        } else {
            out.write_all(&value.bytes).and_then(|()| out.write_all(b"\n"))
        };
        if written.and_then(|()| out.flush()).is_err() {
            // stdout closed, such as a pipe into head: stop quietly.
            return 0;
        }
        if value.end {
            return if !value.binary && value.bytes.starts_with(br#"{"error":"#) { 1 } else { 0 };
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
        assert_eq!(request(&words("packets e12")).unwrap(), r#"{"op":"packets","link":"e12"}"#);
        assert_eq!(request(&words("packet e12 40")).unwrap(), r#"{"op":"packet","link":"e12","seq":40}"#);
        assert_eq!(request(&words("events 7")).unwrap(), r#"{"op":"events","after":7}"#);
        assert_eq!(request(&words("watch 0")).unwrap(), r#"{"op":"watch","after":0}"#);
        assert!(request(&words("packet e12 x")).is_err());
        assert!(request(&words("fly")).is_err());
    }

    #[test]
    fn world_flag() {
        let (w, rest) = take_world(&words("--world unix:/run/w.sock watch")).unwrap();
        assert_eq!((world_path(&w).unwrap(), rest), ("/run/w.sock".to_owned(), words("watch")));
        assert_eq!(world_path("tls:x:1").unwrap_err(), r#"--world: expected unix:<path>, not "tls:x:1""#);
        assert!(world_path("unix:").is_err());
        assert!(take_world(&words("graph")).is_err());
    }
}
