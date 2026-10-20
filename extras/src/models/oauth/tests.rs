use super::*;
use std::io::{Read, Write};

fn directory() -> std::path::PathBuf {
    let mut bytes = [0; 8];
    fictionet::random_bytes(&mut bytes).unwrap();
    let path = std::env::temp_dir().join(format!("oauth-{}", u64::from_le_bytes(bytes)));
    std::fs::create_dir(&path).unwrap();
    path
}
fn tokens(expiration: u64) -> Tokens {
    let mut tokens = Tokens::new(
        Secret::new("access", "sk-ant-oat01-host-access".into()).unwrap(),
        Secret::new("refresh", "host-refresh".into()).unwrap(),
        expiration,
    );
    tokens.scopes = vec!["user:inference".into()];
    tokens.plan = "pro".into();
    tokens.account_id = "account".into();
    tokens
}
fn request(socket: &mut std::net::TcpStream) -> String {
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
    }
    let headers = String::from_utf8(bytes).unwrap();
    let size: usize = headers
        .lines()
        .find_map(|s| s.strip_prefix("content-length: "))
        .unwrap()
        .parse()
        .unwrap();
    let mut body = vec![0; size];
    socket.read_exact(&mut body).unwrap();
    String::from_utf8(body).unwrap()
}
fn answer(socket: &mut std::net::TcpStream, status: u16, body: &str) {
    write!(socket, "HTTP/1.1 {status} Status\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
}

#[test]
fn both_logins_refresh_once_and_persist_rotated_tokens() {
    for login in [Login::Claude, Login::Codex] {
        let dir = directory();
        let path = dir.join("credentials.redb");
        let store = Store::open(&path).unwrap();
        store.put(login, tokens(now() - 1)).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let body: Value = serde_json::from_str(&request(&mut socket)).unwrap();
            assert_eq!(body["refresh_token"], "host-refresh");
            assert_eq!(body["client_id"], login.client());
            answer(
                &mut socket,
                200,
                r#"{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}"#,
            );
        });
        let stored = store.clone();
        fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::from_u64(3)), |cx| async move {
            let authority = OAuth::at(&cx, login, stored.clone(), format!("http://{address}").parse()?)?;
            let mut done = Vec::new();
            for _ in 0..12 {
                let authority = authority.clone();
                let (tx, rx) = oneshot::channel();
                cx.spawn(move |_| async move { let result = authority.ensure_fresh().await; let _ = tx.send(result.is_ok()); Ok(()) });
                done.push(rx);
            }
            for complete in done { assert!(complete.await.unwrap()); }
            assert_eq!(stored.row(login)?.tokens()?.refresh.value, "rotated-refresh");
            let files = authority.guest_files()?;
            assert!(!files[0].1.contains("rotated-access"));
            assert!(!files[0].1.contains("rotated-refresh"));
            let refresh = authority.placeholders.lock().unwrap().refresh.clone();
            let req = Request::post(login.path()).body(Body::from(json!({"grant_type":"refresh_token","client_id":login.client(),"refresh_token":refresh}).to_string()))?;
            let response = Service::call(&mut authority.clone(), req).await?;
            assert_eq!(response.status(), 200);
            let bytes = response.into_body().collect().await?.to_bytes();
            let body: Value = serde_json::from_slice(&bytes)?;
            assert!(authority.accepts(body["access_token"].as_str().unwrap()));
            assert!(!String::from_utf8_lossy(&bytes).contains("rotated-"));
            let stop = authority.stop();
            assert_eq!(stop.status(), 429);
            if login == Login::Claude { assert_eq!(stop.headers()["anthropic-ratelimit-unified-status"], "rejected"); }
            cx.cancel();
            Ok(())
        })).unwrap();
        server.join().unwrap();
        drop(store);
        let reopened = Store::open(&path).unwrap();
        assert_eq!(
            reopened.row(login).unwrap().tokens().unwrap().refresh.value,
            "rotated-refresh"
        );
        drop(reopened);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn stale_success_and_terminal_changes_cannot_replace_a_new_login() {
    let dir = directory();
    let store = Store::open(dir.join("credentials.redb")).unwrap();
    store.put(Login::Claude, tokens(now() + 3600)).unwrap();
    let old = store.row(Login::Claude).unwrap();
    store.delete(Login::Claude).unwrap();
    store.put(Login::Claude, tokens(now() + 7200)).unwrap();
    assert!(
        !store
            .change(Login::Claude, Some(old.revision), old.tokens.clone(), false)
            .unwrap()
    );
    assert!(
        !store
            .change(Login::Claude, Some(old.revision), old.tokens, true)
            .unwrap()
    );
    assert!(
        store
            .row(Login::Claude)
            .unwrap()
            .tokens()
            .unwrap()
            .expires_at
            > now() + 3600
    );
    drop(store);
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn rejected_refresh_preserves_tokens_and_requires_login_only_for_invalid_grant() {
    for (status, body, terminal) in [
        (400, r#"{"error":"invalid_grant"}"#, true),
        (503, r#"{"error":"temporarily_unavailable"}"#, false),
        (200, r#"{"access_token":"changed","expires_in":0}"#, false),
    ] {
        let dir = directory();
        let store = Store::open(dir.join("credentials.redb")).unwrap();
        store.put(Login::Claude, tokens(now() - 1)).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            request(&mut socket);
            answer(&mut socket, status, body);
        });
        let stored = store.clone();
        fictionet::block_on(fictionet::run(fictionet::RunOptions::new(fictionet::Seed::from_u64(4)), |cx| async move {
            let authority = OAuth::at(&cx, Login::Claude, stored.clone(), format!("http://{address}").parse()?)?;
            assert!(authority.ensure_fresh().await.is_err());
            assert!(authority.ensure_fresh().await.is_err());
            let row = stored.row(Login::Claude)?;
            assert_eq!(row.needs_login, terminal);
            assert_eq!(row.tokens.unwrap()["refresh"], "host-refresh");
            stored.put(Login::Claude, tokens(now() + 3600))?;
            assert_eq!(authority.secret().await?.value, "sk-ant-oat01-host-access");
            let response = Service::call(&mut authority.clone(), Request::post(Login::Claude.path()).body(Body::from(r#"{"grant_type":"refresh_token","client_id":"wrong","refresh_token":"host-refresh"}"#))?).await?;
            assert_eq!(response.status(), 400);
            cx.cancel();
            Ok(())
        })).unwrap();
        server.join().unwrap();
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn a_login_during_refresh_wins_over_success_and_rejection() {
    for (status, body) in [
        (
            200,
            r#"{"access_token":"stale-access","refresh_token":"stale-refresh","expires_in":3600}"#,
        ),
        (400, r#"{"error":"invalid_grant"}"#),
        (503, r#"{"error":"temporarily_unavailable"}"#),
    ] {
        let dir = directory();
        let store = Store::open(dir.join("credentials.redb")).unwrap();
        store.put(Login::Claude, tokens(now() - 1)).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (started, ready) = oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            request(&mut socket);
            started.send(()).unwrap();
            released.recv().unwrap();
            answer(&mut socket, status, body);
        });
        let stored = store.clone();
        fictionet::block_on(fictionet::run(
            fictionet::RunOptions::new(fictionet::Seed::from_u64(5)),
            |cx| async move {
                let authority = OAuth::at(
                    &cx,
                    Login::Claude,
                    stored.clone(),
                    format!("http://{address}").parse()?,
                )?;
                let requester = authority.clone();
                let (complete, completed) = oneshot::channel();
                cx.spawn(move |_| async move {
                    let _ = complete.send(requester.ensure_fresh().await);
                    Ok(())
                });
                ready.await.unwrap();
                let mut replacement = tokens(now() + 7200);
                replacement.refresh = Secret::new("refresh", "new-login-refresh".into())?;
                stored.put(Login::Claude, replacement)?;
                release.send(()).unwrap();
                completed.await.unwrap()?;
                assert_eq!(
                    stored.row(Login::Claude)?.tokens()?.refresh.value,
                    "new-login-refresh"
                );
                assert!(stored.flights[0].lock().unwrap().retry_at.is_none());
                cx.cancel();
                Ok(())
            },
        ))
        .unwrap();
        server.join().unwrap();
        drop(store);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
