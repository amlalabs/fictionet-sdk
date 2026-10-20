//! Dedicated OAuth credentials and host-owned refresh for Claude Code and Codex.
//!
//! Open a private store such as `.ax/credentials.redb` and explicitly install a
//! dedicated login with [`Store::put`]. This module never discovers or reads a
//! user's CLI login files. All mutations use a durable revision, including
//! deletion, so an old refresh cannot replace a later login.
//!
//! Create an [`OAuth`] authority for each login, mount it at [`Login::host`],
//! and mount [`Model::oauth`] at the model provider's hostname. Install only
//! [`OAuth::guest_files`] in the guest, with owner-only permissions. Refresh
//! starts ten minutes before expiry and survives cancellation of a requester;
//! cancelling the world's context shuts down the authority.
//!
//! Subscription stops use the unified limit headers exercised by
//! [Claude clients](https://github.com/router-for-me/CLIProxyAPI/blob/main/internal/runtime/executor/claude_executor_ratelimit_test.go)
//! and the `usage_limit_reached` body parsed by
//! [Codex](https://github.com/openai/codex/blob/main/codex-rs/codex-api/src/api_bridge.rs).

use super::*;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Notify, oneshot};

const ACCOUNTS: TableDefinition<&str, &[u8]> = TableDefinition::new("accounts");
const LEAD: u64 = 600;

/// The login whose refresh protocol the authority speaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Login {
    /// Claude subscription login.
    Claude,
    /// Codex ChatGPT login.
    Codex,
}
impl Login {
    fn index(self) -> usize {
        match self {
            Self::Claude => 0,
            Self::Codex => 1,
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
        }
    }
    /// The token server's hostname.
    pub fn host(self) -> &'static str {
        match self {
            Self::Claude => "platform.claude.com",
            Self::Codex => "auth.openai.com",
        }
    }
    fn path(self) -> &'static str {
        match self {
            Self::Claude => "/v1/oauth/token",
            Self::Codex => "/oauth/token",
        }
    }
    fn client(self) -> &'static str {
        match self {
            Self::Claude => "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
            Self::Codex => "app_EMoamEEZ73f0CkXaXp7hrann",
        }
    }
}

/// Tokens from a dedicated login. Formatting secrets never prints their values.
#[derive(Clone, Debug)]
pub struct Tokens {
    /// The provider's access token.
    pub access: Secret,
    /// The refresh token, retained only in the host store.
    pub refresh: Secret,
    /// Access expiration in Unix seconds.
    pub expires_at: u64,
    /// Granted scopes, preserved during refresh.
    pub scopes: Vec<String>,
    /// Subscription type, such as `max` or `pro`.
    pub plan: String,
    /// ChatGPT account identity for Codex.
    pub account_id: String,
    /// Codex's identity token, if returned by the login.
    pub id_token: Option<Secret>,
}
impl Tokens {
    /// Starts a login with no optional account metadata.
    pub fn new(access: Secret, refresh: Secret, expires_at: u64) -> Self {
        Self {
            access,
            refresh,
            expires_at,
            scopes: Vec::new(),
            plan: String::new(),
            account_id: String::new(),
            id_token: None,
        }
    }
}
#[derive(Serialize, Deserialize, Default)]
struct Row {
    revision: u64,
    tokens: Option<Value>,
    needs_login: bool,
}
impl Row {
    fn tokens(&self) -> fictionet::Result<Tokens> {
        if self.needs_login {
            return Err(Error::msg("OAuth login must be renewed"));
        }
        let v = self
            .tokens
            .as_ref()
            .ok_or_else(|| Error::msg("No dedicated OAuth login is stored"))?;
        let secret = |key, name| Secret::new(name, v[key].as_str().unwrap_or_default().to_owned());
        Ok(Tokens {
            access: secret("access", "OAuth access token")?,
            refresh: secret("refresh", "OAuth refresh token")?,
            expires_at: v["expires_at"]
                .as_u64()
                .ok_or_else(|| Error::msg("Stored OAuth expiration is invalid"))?,
            scopes: serde_json::from_value(v["scopes"].clone())
                .map_err(|_| Error::msg("Stored OAuth scopes are invalid"))?,
            plan: v["plan"].as_str().unwrap_or_default().into(),
            account_id: v["account_id"].as_str().unwrap_or_default().into(),
            id_token: v["id_token"]
                .as_str()
                .map(|s| Secret::new("OAuth identity token", s.into()))
                .transpose()?,
        })
    }
}
fn encoded(tokens: &Tokens) -> Value {
    json!({"access":tokens.access.value,"refresh":tokens.refresh.value,"expires_at":tokens.expires_at,
        "scopes":tokens.scopes,"plan":tokens.plan,"account_id":tokens.account_id,
        "id_token":tokens.id_token.as_ref().map(|s| &s.value)})
}
#[derive(Default)]
struct Flight {
    waiters: Option<Vec<oneshot::Sender<()>>>,
    retry_at: Option<Instant>,
}
/// A private ReDB store shared by both authorities and all their clones.
/// Keep one store handle for a file; ReDB excludes other processes.
pub struct Store {
    db: redb::Database,
    flights: [Mutex<Flight>; 2],
    wake: [Notify; 2],
}
impl Store {
    /// Opens a credential database with owner-only file permissions on Unix.
    pub fn open(path: impl AsRef<Path>) -> fictionet::Result<Arc<Self>> {
        let path = path.as_ref();
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        drop(file);
        let db = redb::Database::create(path)?;
        let tx = db.begin_write()?;
        tx.open_table(ACCOUNTS)?;
        tx.commit()?;
        Ok(Arc::new(Self {
            db,
            flights: Default::default(),
            wake: Default::default(),
        }))
    }
    fn row(&self, login: Login) -> fictionet::Result<Row> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(ACCOUNTS)?;
        table
            .get(login.name())?
            .map(|v| {
                serde_json::from_slice(v.value()).map_err(|_| Error::msg("Invalid OAuth store row"))
            })
            .unwrap_or(Ok(Row::default()))
    }
    fn change(
        &self,
        login: Login,
        expected: Option<u64>,
        tokens: Option<Value>,
        needs_login: bool,
    ) -> fictionet::Result<bool> {
        let tx = self.db.begin_write()?;
        {
            let mut table = tx.open_table(ACCOUNTS)?;
            let old: Row = table
                .get(login.name())?
                .map(|v| serde_json::from_slice(v.value()))
                .transpose()
                .map_err(|_| Error::msg("Invalid OAuth store row"))?
                .unwrap_or_default();
            if expected.is_some_and(|revision| old.revision != revision) {
                return Ok(false);
            }
            let next = Row {
                revision: old
                    .revision
                    .checked_add(1)
                    .ok_or_else(|| Error::msg("OAuth revision exhausted"))?,
                tokens,
                needs_login,
            };
            let data = serde_json::to_vec(&next)?;
            table.insert(login.name(), data.as_slice())?;
        }
        tx.commit()?;
        self.wake[login.index()].notify_one();
        Ok(true)
    }
    /// Replaces a dedicated login and invalidates any refresh already in flight.
    pub fn put(&self, login: Login, tokens: Tokens) -> fictionet::Result<()> {
        self.change(login, None, Some(encoded(&tokens)), false)?;
        self.flights[login.index()].lock().unwrap().retry_at = None;
        Ok(())
    }
    /// Removes credentials without resetting the revision.
    pub fn delete(&self, login: Login) -> fictionet::Result<()> {
        self.change(login, None, None, false)?;
        Ok(())
    }
}

struct Placeholders {
    access: String,
    previous: Option<String>,
    refresh: String,
    expires_at: u64,
}
/// A shared refresh authority and guest token endpoint.
#[derive(Clone)]
pub struct OAuth {
    cx: Cx,
    login: Login,
    store: Arc<Store>,
    forward: web::Forward,
    authority: String,
    placeholders: Arc<Mutex<Placeholders>>,
}
impl OAuth {
    pub(super) fn login(&self) -> Login {
        self.login
    }
    pub(super) fn placeholder(&self) -> String {
        self.placeholders.lock().unwrap().access.clone()
    }

    /// Starts proactive refresh against the login's real token server.
    pub fn new(cx: &Cx, login: Login, store: Arc<Store>) -> fictionet::Result<Self> {
        Self::at(
            cx,
            login,
            store,
            format!("https://{}", login.host()).parse()?,
        )
    }
    /// Starts an authority using a supplied token server, including a local one.
    pub fn at(
        cx: &Cx,
        login: Login,
        store: Arc<Store>,
        origin: http::Uri,
    ) -> fictionet::Result<Self> {
        let tokens = store.row(login)?.tokens()?;
        let authority = origin
            .authority()
            .ok_or_else(|| Error::msg("Token server needs an authority"))?
            .to_string();
        let result = Self {
            cx: cx.clone(),
            login,
            store,
            forward: web::forward(cx, origin)?,
            authority,
            placeholders: Arc::new(Mutex::new(Placeholders {
                access: placeholder(cx, login, &tokens),
                previous: None,
                expires_at: tokens.expires_at,
                refresh: Credential::api_key(cx, tokens.refresh).placeholder,
            })),
        };
        let scheduler = result.clone();
        cx.spawn(move |cx| async move {
            loop {
                let row = scheduler.store.row(login)?;
                let delay = match row.tokens() {
                    Ok(tokens) => {
                        if tokens.expires_at <= now().saturating_add(LEAD) {
                            let _ = scheduler.ensure_fresh().await;
                        }
                        scheduler
                            .store
                            .row(login)?
                            .tokens()
                            .map(|t| {
                                t.expires_at
                                    .saturating_sub(now().saturating_add(LEAD))
                                    .max(60)
                            })
                            .unwrap_or(60)
                    }
                    Err(_) => 60,
                };
                let deadline = cx.now() + Duration::from_secs(delay);
                match cx
                    .race(
                        Some(deadline),
                        scheduler.store.wake[login.index()].notified(),
                    )
                    .await
                {
                    Err(fictionet::RaceError::Cancelled) => return Ok(()),
                    _ => continue,
                }
            }
        });
        Ok(result)
    }
    /// Ensures the stored token is usable, coalescing concurrent refresh requests.
    /// The refresh belongs to the run, so cancelling a requester cannot discard a rotation.
    pub async fn ensure_fresh(&self) -> fictionet::Result<()> {
        let tokens = self.store.row(self.login)?.tokens()?;
        if tokens.expires_at > now().saturating_add(LEAD) {
            return Ok(());
        }
        let receiver = {
            let mut flight = self.store.flights[self.login.index()].lock().unwrap();
            if flight
                .retry_at
                .is_some_and(|deadline| deadline > Instant::now())
            {
                return if tokens.expires_at > now() {
                    Ok(())
                } else {
                    Err(Error::msg("OAuth token refresh is temporarily unavailable"))
                };
            }
            let (tx, rx) = oneshot::channel();
            if let Some(waiters) = &mut flight.waiters {
                waiters.push(tx);
            } else {
                flight.waiters = Some(vec![tx]);
                let authority = self.clone();
                self.cx.spawn(move |_| async move {
                    let revision = authority.store.row(authority.login)?.revision;
                    let result = authority.refresh().await;
                    let mut flight = authority.store.flights[authority.login.index()]
                        .lock()
                        .unwrap();
                    if result.is_err() && authority.store.row(authority.login)?.revision == revision
                    {
                        flight.retry_at = Some(Instant::now() + Duration::from_secs(60));
                    }
                    for waiter in flight.waiters.take().unwrap_or_default() {
                        let _ = waiter.send(());
                    }
                    Ok(())
                });
            }
            rx
        };
        self.cx
            .race(None, receiver)
            .await
            .map_err(|_| Error::msg("OAuth refresh was cancelled"))?
            .map_err(|_| Error::msg("OAuth refresh was interrupted"))?;
        let current = self.store.row(self.login)?.tokens()?;
        if current.expires_at <= now() {
            return Err(Error::msg("OAuth token refresh is temporarily unavailable"));
        }
        Ok(())
    }
    async fn refresh(&self) -> fictionet::Result<()> {
        let row = self.store.row(self.login)?;
        let mut tokens = row.tokens()?;
        if tokens.expires_at > now().saturating_add(LEAD) {
            return Ok(());
        }
        let mut body = json!({"grant_type":"refresh_token","refresh_token":tokens.refresh.value,"client_id":self.login.client()});
        if self.login == Login::Claude && !tokens.scopes.is_empty() {
            body["scope"] = json!(tokens.scopes.join(" "));
        }
        let request = Request::post(self.login.path())
            .header("host", &self.authority)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))?;
        let exchange = async {
            let response = self.forward.clone().call(request).await?;
            let status = response.status();
            let bytes = http_body_util::Limited::new(response.into_body(), 64 * 1024)
                .collect()
                .await
                .map_err(|_| Error::msg("OAuth response could not be read"))?
                .to_bytes();
            Ok::<_, Error>((status, bytes))
        };
        let (status, bytes) = self
            .cx
            .race(Some(self.cx.now() + Duration::from_secs(20)), exchange)
            .await
            .map_err(|_| Error::msg("OAuth token server did not respond"))?
            .map_err(|_| Error::msg("OAuth token server could not be reached"))?;
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| Error::msg("Invalid OAuth token response"))?;
        if value["error"] == "invalid_grant"
            || (self.login == Login::Codex
                && (status == http::StatusCode::UNAUTHORIZED
                    || matches!(
                        value["error"]["code"].as_str(),
                        Some(
                            "refresh_token_expired"
                                | "refresh_token_reused"
                                | "refresh_token_invalidated"
                        )
                    )))
        {
            self.store
                .change(self.login, Some(row.revision), row.tokens, true)?;
            return Err(Error::msg("OAuth login must be renewed"));
        }
        if !status.is_success() {
            return Err(Error::msg("OAuth token server refused refresh"));
        }
        tokens.access = Secret::new(
            "OAuth access token",
            value["access_token"].as_str().unwrap_or_default().into(),
        )?;
        if let Some(refresh) = value["refresh_token"].as_str() {
            tokens.refresh = Secret::new("OAuth refresh token", refresh.into())?;
        }
        if let Some(id) = value["id_token"].as_str() {
            tokens.id_token = Some(Secret::new("OAuth identity token", id.into())?);
        }
        let expires = value["expires_in"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or_else(|| Error::msg("OAuth response has no valid expiration"))?;
        tokens.expires_at = now()
            .checked_add(expires)
            .ok_or_else(|| Error::msg("Invalid OAuth expiration"))?;
        if let Some(scope) = value["scope"].as_str() {
            tokens.scopes = scope.split_whitespace().map(str::to_owned).collect();
        }
        self.store.change(
            self.login,
            Some(row.revision),
            Some(encoded(&tokens)),
            false,
        )?;
        Ok(())
    }
    pub(super) async fn secret(&self) -> fictionet::Result<Secret> {
        self.ensure_fresh().await?;
        Ok(self.store.row(self.login)?.tokens()?.access)
    }
    pub(super) fn accepts(&self, value: &str) -> bool {
        let placeholders = self.placeholders.lock().unwrap();
        value == placeholders.access || placeholders.previous.as_deref() == Some(value)
    }
    /// Placeholder-only credential files, relative to the guest user's home.
    pub fn guest_files(&self) -> fictionet::Result<Vec<(&'static str, String)>> {
        let tokens = self.store.row(self.login)?.tokens()?;
        let mut placeholders = self.placeholders.lock().unwrap();
        if self.login == Login::Codex && placeholders.expires_at != tokens.expires_at {
            let next = placeholder(&self.cx, self.login, &tokens);
            placeholders.previous = Some(std::mem::replace(&mut placeholders.access, next));
            placeholders.expires_at = tokens.expires_at;
        }
        let (path, value) = match self.login {
            Login::Claude => (
                ".claude/.credentials.json",
                json!({"claudeAiOauth":{
                "accessToken":placeholders.access,"refreshToken":placeholders.refresh,"expiresAt":tokens.expires_at.saturating_mul(1000),
                "scopes":tokens.scopes,"subscriptionType":tokens.plan}}),
            ),
            Login::Codex => (
                ".codex/auth.json",
                json!({"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{
                "access_token":placeholders.access,"refresh_token":placeholders.refresh,"id_token":identity(&self.cx, &tokens),"account_id":tokens.account_id}}),
            ),
        };
        Ok(vec![(path, value.to_string())])
    }
    async fn serve(self, request: Request<Body>) -> fictionet::Result<Response<Body>> {
        if request.method() != http::Method::POST || request.uri().path() != self.login.path() {
            return Ok(oauth_error(404, "invalid_request"));
        }
        let bytes = http_body_util::Limited::new(request.into_body(), 64 * 1024)
            .collect()
            .await
            .map_err(|_| Error::msg("OAuth request is too large"))?
            .to_bytes();
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if value["grant_type"] != "refresh_token"
            || value["client_id"] != self.login.client()
            || value["refresh_token"].as_str()
                != Some(self.placeholders.lock().unwrap().refresh.as_str())
        {
            return Ok(oauth_error(400, "invalid_grant"));
        }
        if self.ensure_fresh().await.is_err() {
            let row = self.store.row(self.login)?;
            return Ok(oauth_error(
                400,
                if row.needs_login || row.tokens.is_none() {
                    "invalid_grant"
                } else {
                    "temporarily_unavailable"
                },
            ));
        }
        let tokens = self.store.row(self.login)?.tokens()?;
        let mut placeholders = self.placeholders.lock().unwrap();
        let next = placeholder(&self.cx, self.login, &tokens);
        placeholders.previous = Some(std::mem::replace(&mut placeholders.access, next));
        placeholders.expires_at = tokens.expires_at;
        let mut response = json!({"token_type":"Bearer","access_token":placeholders.access,"refresh_token":placeholders.refresh,
            "expires_in":tokens.expires_at.saturating_sub(now()),"scope":tokens.scopes.join(" ")});
        if self.login == Login::Codex {
            response["id_token"] = json!(identity(&self.cx, &tokens));
        }
        Ok(Response::builder()
            .header("content-type", "application/json")
            .body(Body::from(response.to_string()))?)
    }
    pub(super) fn account(&self) -> fictionet::Result<String> {
        Ok(self.store.row(self.login)?.tokens()?.account_id)
    }
    pub(super) fn stop(&self) -> Response<Body> {
        let reset = now() + 5 * 3600;
        match self.login {
            Login::Claude => {
                let mut response = Provider::Anthropic.error(
                    429,
                    "rate_limit_error",
                    "Number of requests has exceeded your 5-hour rate limit.",
                );
                for (name, value) in [
                    ("anthropic-ratelimit-unified-status", "rejected".into()),
                    ("anthropic-ratelimit-unified-5h-status", "rejected".into()),
                    ("anthropic-ratelimit-unified-5h-reset", reset.to_string()),
                    (
                        "anthropic-ratelimit-unified-representative-claim",
                        "five_hour".into(),
                    ),
                    ("anthropic-ratelimit-unified-reset", reset.to_string()),
                    ("retry-after", "18000".into()),
                    ("x-should-retry", "false".into()),
                ] {
                    response
                        .headers_mut()
                        .insert(name, value.parse().expect("quota header"));
                }
                response
            }
            Login::Codex => {
                let plan = self
                    .store
                    .row(self.login)
                    .and_then(|r| r.tokens())
                    .map(|t| t.plan)
                    .unwrap_or_default();
                Response::builder().status(429).header("content-type", "application/json")
                    .header("x-codex-primary-used-percent", "100.0").header("x-codex-primary-window-minutes", "300")
                    .header("x-codex-primary-reset-at", reset.to_string())
                    .body(Body::from(json!({"error":{"type":"usage_limit_reached","message":"The usage limit has been reached","plan_type":plan,"resets_at":reset,"limit_window_minutes":300}}).to_string())).expect("quota response")
            }
        }
    }
}
impl Service<Request<Body>> for OAuth {
    type Response = Response<Body>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = fictionet::Result<Response<Body>>> + Send>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<fictionet::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn call(&mut self, request: Request<Body>) -> Self::Future {
        Box::pin(self.clone().serve(request))
    }
}
impl httpd::Handler for OAuth {
    fn call(&self, request: Request<Body>, exchange: &mut httpd::Exchange<'_>) -> httpd::Reply {
        httpd::tower(self.clone()).call(request, exchange)
    }
}
fn oauth_error(status: u16, error: &str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(json!({"error":error}).to_string()))
        .expect("OAuth response")
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn jwt(cx: &Cx, value: Value) -> String {
    let encode = |bytes: &[u8]| {
        fictionet::stdlib::codec::base64::encode(bytes)
            .trim_end_matches('=')
            .replace('+', "-")
            .replace('/', "_")
    };
    let mut signature = [0; 256];
    cx.fill_random(&mut signature);
    format!(
        "{}.{}.{}",
        encode(br#"{"alg":"RS256","typ":"JWT"}"#),
        encode(value.to_string().as_bytes()),
        encode(&signature)
    )
}
fn identity(cx: &Cx, tokens: &Tokens) -> String {
    jwt(
        cx,
        json!({"exp":tokens.expires_at,"https://api.openai.com/auth":{"chatgpt_account_id":tokens.account_id,"chatgpt_plan_type":tokens.plan}}),
    )
}
fn placeholder(cx: &Cx, login: Login, tokens: &Tokens) -> String {
    if login == Login::Codex {
        jwt(
            cx,
            json!({"exp":tokens.expires_at,"iat":now(),"jti":format!("{:016x}", cx.random_u64())}),
        )
    } else {
        Credential::api_key(cx, tokens.access.clone()).placeholder
    }
}

#[cfg(test)]
mod tests;
