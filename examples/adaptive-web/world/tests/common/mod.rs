use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    net::TcpListener,
    path::Path,
    process::{Child, Command, Stdio},
};

pub struct Python {
    child: Child,
    pub hello: Value,
    pub port: u16,
}
impl Python {
    pub fn start(seed: &str, seeds: &Path, store: &Path) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let child = Command::new("python3")
            .arg("backend.py")
            .arg(port.to_string())
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("backend"))
            .env("ADAPTIVE_WEB_SEED", seed)
            .env("ADAPTIVE_WEB_SEEDS", seeds)
            .env("ADAPTIVE_WEB_GENERATOR", "stub")
            .env("ADAPTIVE_WEB_STORE", store)
            .env_remove("ADAPTIVE_WEB_PREFETCH")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut python = Self {
            child,
            hello: Value::Null,
            port,
        };
        let stdout = python.child.stdout.take().unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            BufReader::new(stdout).read_line(&mut line).unwrap();
            let _ = tx.send(line);
        });
        let line = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("backend hello timed out");
        reader.join().unwrap();
        python.hello =
            serde_json::from_str(&line).unwrap_or_else(|e| panic!("backend hello {line:?}: {e}"));
        python
    }
}
impl Drop for Python {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
