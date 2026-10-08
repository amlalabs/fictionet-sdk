use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

/// Collects lines and waits until one contains the text.
pub fn logged(input: impl Read + Send + 'static, text: &'static str) -> std::thread::JoinHandle<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut log = String::new();
        let mut ready = Some(tx);
        for line in BufReader::new(input).lines() {
            let line = line.unwrap();
            if line.contains(text) && let Some(tx) = ready.take() {
                tx.send(()).unwrap();
            }
            log.push_str(&line);
            log.push('\n');
        }
        log
    });
    rx.recv_timeout(Duration::from_secs(10)).expect("the child did not log readiness");
    reader
}
