use super::*;
use base64::Engine;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use tungstenite::{Message, WebSocket, stream::MaybeTlsStream};

pub struct Browser {
    _child: ChildGuard,
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
    session: Option<String>,
    replies: BTreeMap<u64, Value>,
    pending: BTreeSet<u64>,
    loaded: bool,
    video: Option<ChildGuard>,
    frame: Vec<u8>,
    video_start: Option<Instant>,
    frames: u64,
    scan: Option<Scan>,
    out: PathBuf,
}

impl Browser {
    pub fn launch(profile: &Path, out: &Path) -> Result<Self> {
        let chromium = std::env::var("CHROMIUM").unwrap_or_else(|_| "chromium".into());
        let child = cmd(
            &chromium,
            &[
                "--headless",
                "--disable-dev-shm-usage",
                "--remote-debugging-port=0",
                "--window-size=1920,1080",
                "--no-first-run",
                "--no-default-browser-check",
                "--password-store=basic",
            ],
        )
        .arg(format!("--user-data-dir={}", profile.display()))
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
        let mut child = ChildGuard(child);
        let stderr = child.0.stderr.take().ok_or("missing Chromium stderr")?;
        let (send, recv) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines() {
                match line {
                    Ok(line) => {
                        if let Some(url) = line.strip_prefix("DevTools listening on ") {
                            if let Err(error) = send.send(url.to_owned()) {
                                eprintln!("Chromium startup receiver closed: {error}");
                            }
                        } else {
                            eprintln!("Chromium: {line}");
                        }
                    }
                    Err(error) => {
                        eprintln!("Chromium stderr: {error}");
                        break;
                    }
                }
            }
        });
        let url = recv.recv_timeout(Duration::from_secs(30))?;
        let (mut socket, _) = tungstenite::connect(url)?;
        match socket.get_mut() {
            MaybeTlsStream::Plain(stream) => {
                stream.set_read_timeout(Some(Duration::from_millis(20)))?
            }
            _ => return Err("expected a local Chromium connection".into()),
        }
        let mut browser = Self {
            _child: child,
            socket,
            next_id: 0,
            session: None,
            replies: BTreeMap::new(),
            pending: BTreeSet::new(),
            loaded: false,
            video: None,
            frame: Vec::new(),
            video_start: None,
            frames: 0,
            scan: None,
            out: out.into(),
        };
        let target = browser.call("Target.createTarget", json!({"url": "about:blank"}))?;
        let attached = browser.call(
            "Target.attachToTarget",
            json!({"targetId": target["targetId"], "flatten": true}),
        )?;
        browser.session = Some(
            attached["sessionId"]
                .as_str()
                .ok_or("missing browser session")?
                .into(),
        );
        browser.call("Page.enable", json!({}))?;
        browser.call("Runtime.enable", json!({}))?;
        browser.call(
            "Emulation.setDeviceMetricsOverride",
            json!({"width":1920,"height":1080,"deviceScaleFactor":1,"mobile":false}),
        )?;
        browser.call("Page.setBypassCSP", json!({"enabled": true}))?;
        Ok(browser)
    }

    fn send(&mut self, method: &str, params: Value) -> Result<u64> {
        self.next_id += 1;
        let mut message = json!({"id": self.next_id, "method": method, "params": params});
        if let Some(session) = &self.session {
            message["sessionId"] = json!(session);
        }
        self.socket
            .send(Message::Text(message.to_string().into()))?;
        Ok(self.next_id)
    }

    fn send_pending(&mut self, method: &str, params: Value) -> Result {
        let id = self.send(method, params)?;
        self.pending.insert(id);
        Ok(())
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.send(method, params)?;
        let start = Instant::now();
        loop {
            if let Some(reply) = self.replies.remove(&id) {
                if let Some(error) = reply.get("error") {
                    return Err(format!("Chromium {method}: {error}").into());
                }
                return Ok(reply["result"].clone());
            }
            if start.elapsed() >= Duration::from_secs(30) {
                return Err(format!("Chromium {method} timed out").into());
            }
            self.pump()?;
        }
    }

    fn pump(&mut self) -> Result {
        match self.socket.read() {
            Ok(Message::Text(text)) => {
                let message: Value = serde_json::from_str(&text)?;
                if let Some(id) = message["id"].as_u64() {
                    if self.pending.remove(&id) {
                        if message.get("error").is_some()
                            || message["result"].get("exceptionDetails").is_some()
                        {
                            return Err(format!("Chromium: {message}").into());
                        }
                    } else {
                        self.replies.insert(id, message);
                    }
                } else {
                    match message["method"].as_str() {
                        Some("Page.loadEventFired") => self.loaded = true,
                        Some("Page.screencastFrame") => {
                            self.flush_video()?;
                            self.frame = base64::engine::general_purpose::STANDARD.decode(
                                message["params"]["data"]
                                    .as_str()
                                    .ok_or("missing frame data")?,
                            )?;
                            self.video_start.get_or_insert_with(Instant::now);
                            self.send_pending(
                                "Page.screencastFrameAck",
                                json!({"sessionId": message["params"]["sessionId"]}),
                            )?;
                        }
                        Some("Runtime.exceptionThrown") => {
                            eprintln!("page error: {}", message["params"]["exceptionDetails"])
                        }
                        Some("Inspector.targetCrashed") => {
                            return Err("Chromium page crashed".into());
                        }
                        _ => {}
                    }
                }
            }
            Ok(Message::Close(_)) => return Err("Chromium closed its connection".into()),
            Ok(_) => {}
            Err(tungstenite::Error::Io(error))
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(error) => return Err(error.into()),
        }
        let lines = self
            .scan
            .as_mut()
            .map(Scan::read)
            .transpose()?
            .unwrap_or_default();
        for line in lines {
            self.send_pending(
                "Runtime.evaluate",
                json!({"expression": format!("rec.write({})", serde_json::to_string(&line)?)}),
            )?;
        }
        self.flush_video()
    }

    fn flush_video(&mut self) -> Result {
        if let (Some(start), Some(video)) = (self.video_start, self.video.as_mut()) {
            let target = (start.elapsed().as_secs_f64() * 25.0).ceil() as u64;
            while self.frames < target {
                video
                    .0
                    .stdin
                    .as_mut()
                    .ok_or("missing video input")?
                    .write_all(&self.frame)?;
                self.frames += 1;
            }
        }
        Ok(())
    }

    pub fn eval(&mut self, expression: &str) -> Result<Value> {
        let reply = self.call(
            "Runtime.evaluate",
            json!({"expression": expression, "returnByValue": true, "awaitPromise": true}),
        )?;
        if let Some(error) = reply.get("exceptionDetails") {
            return Err(format!("JavaScript: {error}").into());
        }
        Ok(reply["result"]["value"].clone())
    }

    pub fn until(&mut self, expression: &str) -> Result {
        let start = Instant::now();
        while self.eval(expression)? != true {
            if start.elapsed() >= Duration::from_secs(30) {
                return Err(format!("waiting for {expression}").into());
            }
            self.pump()?;
        }
        Ok(())
    }

    pub fn navigate(&mut self, url: &str) -> Result {
        self.loaded = false;
        let result = self.call("Page.navigate", json!({"url": url}))?;
        if let Some(error) = result.get("errorText") {
            return Err(format!("navigation: {error}").into());
        }
        let start = Instant::now();
        while !self.loaded {
            if start.elapsed() >= Duration::from_secs(30) {
                return Err("page load timed out".into());
            }
            self.pump()?;
        }
        Ok(())
    }

    pub fn wait(&mut self, seconds: f64) -> Result {
        let start = Instant::now();
        while start.elapsed().as_secs_f64() < seconds {
            self.pump()?;
        }
        Ok(())
    }

    pub fn start_video(&mut self) -> Result {
        File::create(self.out.join("nmap.txt"))?;
        let child = cmd(
            "ffmpeg",
            &[
                "-v",
                "error",
                "-y",
                "-f",
                "image2pipe",
                "-framerate",
                "25",
                "-vcodec",
                "png",
                "-i",
                "pipe:0",
                "-c:v",
                "libvpx-vp9",
                "-deadline",
                "realtime",
                "-cpu-used",
                "8",
                "-b:v",
                "2M",
                "-pix_fmt",
                "yuv420p",
            ],
        )
        .arg(self.out.join("dashboard.webm"))
        .stdin(Stdio::piped())
        .spawn()?;
        self.video = Some(ChildGuard(child));
        self.call(
            "Page.startScreencast",
            json!({"format":"png","maxWidth":1920,"maxHeight":1080,"everyNthFrame":1}),
        )?;
        Ok(())
    }

    pub fn scan(&mut self, compose: &Compose, argv: &[&str]) -> Result {
        if self.scan.is_some() {
            return Err("a scan is already running".into());
        }
        let mut command = compose.command(&["exec", "-T", "scanner"]);
        command.args(argv);
        self.scan = Some(Scan::start(&mut command, argv, &self.out)?);
        Ok(())
    }

    pub fn finish_scan(&mut self) -> Result {
        while self
            .scan
            .as_ref()
            .ok_or("no running scan")?
            .status
            .is_none()
        {
            self.pump()?;
        }
        self.scan.take().unwrap().finish()
    }

    pub fn finish(mut self) -> Result {
        self.call("Page.stopScreencast", json!({}))?;
        self.flush_video()?;
        let mut video = self.video.take().ok_or("recording was not started")?;
        drop(video.0.stdin.take());
        let status = video.0.wait()?;
        if !status.success() {
            return Err(format!("video encoding exited with {status}").into());
        }
        if self.frames == 0 {
            return Err("Chromium recorded no video frames".into());
        }
        Ok(())
    }
}
