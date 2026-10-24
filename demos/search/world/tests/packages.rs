//! Real pip installation through the world's handler, without an upstream transport.

use fictionet::stdlib::web::{self, Body};
use http_body_util::BodyExt;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::PathBuf,
    process::Command,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};
use web_world::{
    handler::Handler,
    pages::{Pages, Seed},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
type Requests = Arc<Mutex<Vec<(String, String, u16)>>>;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn connection(
    socket: TcpStream,
    pages: Arc<Pages>,
    configs: &HashMap<String, Arc<rustls::ServerConfig>>,
    requests: Requests,
) -> Result {
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut reader = BufReader::new(socket);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let authority = line
        .strip_prefix("CONNECT ")
        .and_then(|line| line.split_whitespace().next())
        .ok_or("expected CONNECT")?;
    let host = authority
        .strip_suffix(":443")
        .ok_or("expected HTTPS")?
        .to_owned();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err("incomplete proxy request".into());
        }
        if line == "\r\n" {
            break;
        }
    }
    let Some(config) = configs.get(&host) else {
        reader
            .get_mut()
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")?;
        return Err(format!("uncaptured host {host}").into());
    };
    reader
        .get_mut()
        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")?;
    let tls = rustls::ServerConnection::new(config.clone())?;
    let mut reader = BufReader::new(rustls::StreamOwned::new(tls, reader.into_inner()));
    line.clear();
    reader.read_line(&mut line)?;
    let mut parts = line.split_whitespace();
    let method: http::Method = parts.next().ok_or("missing method")?.parse()?;
    let path = parts.next().ok_or("missing path")?.to_owned();
    let mut request = http::Request::builder().method(method).uri(&path);
    let mut length = 0;
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Err("incomplete request".into());
        }
        if line == "\r\n" {
            break;
        }
        let (name, value) = line.split_once(':').ok_or("invalid header")?;
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse()?;
        }
        request = request.header(name, value.trim());
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let request = request.body(Body::from(body))?;
    let request_host = host.clone();
    let output = Arc::new(Mutex::new(None));
    let captured = output.clone();
    fictionet::block_on(fictionet::run(
        fictionet::Seed::from_u64(9),
        |cx| async move {
            use web::httpd::{self, Handler as _};
            let sites = httpd::VirtualHosts::new();
            let mut site = httpd::VHost::new(httpd::tower(Handler::new(&cx, pages)));
            site.https = true;
            sites.insert(&request_host, site);
            let mut conn = fictionet::stdlib::services::serve::ConnInfo::default();
            conn.tls = true;
            let reply = sites.call(request, &mut httpd::Exchange::new(cx.now(), &cx, &conn));
            let response = match reply {
                httpd::Reply::Now(response) => response,
                httpd::Reply::Later(work) => work(cx).await?,
            };
            let (parts, body) = response.into_parts();
            let body = body.collect().await?.to_bytes();
            *captured.lock().unwrap() = Some((parts, body));
            Ok(())
        },
    ))?;
    let (parts, body) = output.lock().unwrap().take().unwrap();
    requests
        .lock()
        .unwrap()
        .push((host, path, parts.status.as_u16()));
    let socket = reader.get_mut();
    write!(socket, "HTTP/1.1 {}\r\n", parts.status)?;
    for (name, value) in &parts.headers {
        if name != http::header::CONNECTION {
            write!(socket, "{name}: {}\r\n", value.to_str()?)?;
        }
    }
    socket.write_all(b"Connection: close\r\n\r\n")?;
    socket.write_all(&body)?;
    socket.conn.send_close_notify();
    socket.flush()?;
    Ok(())
}

#[test]
fn pip_installs_research_tools_and_git_clones_captured_repositories_offline() -> Result {
    let downloads = std::env::var_os("SEARCH_DOWNLOADS")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../downloads"));
    let python = std::env::var_os("SEARCH_PYTHON")
        .map(PathBuf::from)
        .unwrap_or_else(|| downloads.join("package-capture/bin/python"));
    let mut seed = Seed::builtin("security")?;
    seed.date = time::OffsetDateTime::now_utc().date().to_string();
    let pages = Arc::new(Pages::from_corpus(seed, &downloads, None)?);
    let hosts = [
        "pypi.org",
        "files.pythonhosted.org",
        "github.com",
        "codeload.github.com",
    ];
    for host in hosts {
        assert!(pages.serves_host(host), "{host}");
    }
    fictionet::block_on(fictionet::lab(fictionet::Seed::from_u64(11), |cx| {
        let pages = pages.clone();
        async move {
            for host in hosts {
                for path in ["/no-such-project-or-page", "/404"] {
                    let response = pages.handle(&cx, "GET", host, path, None).await;
                    assert_eq!(response.status, 404, "{host}{path}");
                    let body = String::from_utf8_lossy(&response.body);
                    assert!(!body.contains("<center>nginx</center>"), "{host}{path}");
                    if host == "github.com" {
                        assert!(body.contains("GitHub"));
                    }
                }
            }
            Ok(())
        }
    }))?;
    let dir = Directory(std::env::temp_dir().join(format!(
            "search-packages-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_nanos()
        )));
    std::fs::create_dir_all(&dir.0)?;
    let configs = Arc::new(Mutex::new(HashMap::new()));
    let shared = configs.clone();
    let pem = dir.0.join("ca.pem");
    fictionet::block_on(fictionet::lab(
        fictionet::Seed::from_u64(7),
        |cx| async move {
            let now = time::OffsetDateTime::now_utc().unix_timestamp();
            let ca = fictionet_extras::zscaler::zscaler(
                &cx,
                fictionet_extras::zscaler::DEFAULT_CLOUD,
                now,
            )?;
            std::fs::write(pem, ca.root_pem())?;
            for host in hosts {
                let leaf = ca.issue(&cx, &[host], now)?;
                let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(leaf.chain, leaf.key)?;
                shared
                    .lock()
                    .unwrap()
                    .insert(host.to_owned(), Arc::new(config));
            }
            Ok(())
        },
    ))?;
    let configs = Arc::try_unwrap(configs).unwrap().into_inner().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    let requests: Requests = Default::default();
    let observed = requests.clone();
    let server = std::thread::spawn(move || {
        let mut workers = Vec::new();
        for socket in listener.incoming() {
            let socket = socket.unwrap();
            // A shutdown connection has no request bytes.
            let mut byte = [0];
            if socket.peek(&mut byte).unwrap() == 0 {
                break;
            }
            let (pages, requests, configs) = (pages.clone(), observed.clone(), configs.clone());
            workers.push(std::thread::spawn(move || {
                connection(socket, pages, &configs, requests)
            }));
        }
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Result<Vec<_>>>()
    });
    let proxy = format!("http://{address}");
    let cert = dir.0.join("ca.pem");
    let site = dir.0.join("site");
    let install = Command::new(&python)
        .args([
            "-m",
            "pip",
            "--isolated",
            "--disable-pip-version-check",
            "--no-cache-dir",
            "--proxy",
            &proxy,
            "--cert",
        ])
        .arg(&cert)
        .args([
            "install",
            "--index-url",
            "https://pypi.org/simple",
            "--ignore-installed",
            "--only-binary=:all:",
            "--target",
        ])
        .arg(&site)
        .args([
            "requests",
            "pandas",
            "numpy",
            "matplotlib",
            "beautifulsoup4",
            "scipy",
            "networkx",
            "pyyaml",
            "packaging",
            "rich",
            "pytest",
        ])
        .output()?;
    let imported = if install.status.success() {
        Some(Command::new(&python).env("PYTHONPATH", &site).env("HTTPS_PROXY", &proxy).env("NO_PROXY", "").env("SSL_CERT_FILE", &cert)
            .arg("-c").arg("import requests,pandas,numpy,matplotlib,bs4,scipy,networkx,yaml,packaging,rich,pytest,urllib.request,io,tarfile; matplotlib.use('Agg'); import matplotlib.pyplot as plt; assert numpy.arange(5).sum()==10; assert bs4.BeautifulSoup('<h1>Source</h1>','html.parser').h1.text=='Source'; plt.plot([1,2,3]); plt.savefig(io.BytesIO(),format='png'); data=urllib.request.urlopen('https://github.com/psf/requests/archive/refs/tags/v2.32.3.tar.gz').read(); assert any(p.endswith('/requests/__init__.py') for p in tarfile.open(fileobj=io.BytesIO(data)).getnames()); print('imports, plot and archive passed')")
            .output()?)
    } else {
        None
    };
    let mut clones = Vec::new();
    for (repo, tag, file) in [
        ("psf/requests", "v2.32.3", "src/requests/__init__.py"),
        (
            "networkx/networkx",
            "networkx-3.4.2",
            "networkx/__init__.py",
        ),
        ("pallets/click", "8.1.8", "src/click/__init__.py"),
    ] {
        for shallow in [false, true] {
            let destination = dir.0.join(format!("{}-{shallow}", repo.replace('/', "-")));
            let mut command = Command::new("git");
            command
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("NO_PROXY", "")
                .env("no_proxy", "")
                .args([
                    "-c",
                    &format!("http.proxy={proxy}"),
                    "-c",
                    &format!("http.sslCAInfo={}", cert.display()),
                    "clone",
                ]);
            if shallow {
                command.args(["--depth", "1", "--branch", tag]);
            }
            let output = command
                .arg(format!("https://github.com/{repo}"))
                .arg(&destination)
                .output()?;
            clones.push((repo, shallow, output, destination.join(file).is_file()));
        }
    }
    let shutdown = TcpStream::connect(address)?;
    shutdown.shutdown(std::net::Shutdown::Both)?;
    server.join().unwrap()?;
    assert!(
        install.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr)
    );
    let imported = imported.unwrap();
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    for (repo, shallow, output, exists) in clones {
        assert!(
            output.status.success(),
            "clone {repo} shallow={shallow}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(exists, "clone {repo} contains its source");
    }
    let requests = requests.lock().unwrap();
    for host in hosts {
        assert!(requests.iter().any(|(name, _, _)| name == host), "{host}");
    }
    assert!(
        requests
            .iter()
            .all(|(_, _, status)| matches!(status, 200 | 301 | 302)),
        "{requests:?}"
    );
    assert!(
        requests
            .iter()
            .any(|(host, path, status)| host == "github.com"
                && path.ends_with("/git-upload-pack")
                && *status == 200)
    );
    eprintln!(
        "{} captured HTTP requests; {}",
        requests.len(),
        String::from_utf8_lossy(&imported.stdout)
    );
    Ok(())
}
