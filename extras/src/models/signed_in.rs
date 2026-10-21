//! Keep the guest's own sign in while answering its web tools in the world.

use super::*;
use std::collections::HashMap;

/// A model handler for guests that obtain their own API key or OAuth token.
/// Each credential keeps a model session, including sealed search history.
#[derive(Clone)]
pub struct SignedIn {
    cx: Cx,
    provider: Provider,
    origin: http::Uri,
    engine: Arc<dyn Engine>,
    sessions: Arc<Mutex<HashMap<String, Model>>>,
}

impl SignedIn {
    /// Use the provider's normal upstream, preserving guest authentication.
    pub fn new(cx: &Cx, provider: Provider, engine: Arc<dyn Engine>) -> fictionet::Result<Self> {
        Self::at(
            cx,
            provider,
            engine,
            format!("https://{}", provider.host()).parse()?,
        )
    }

    /// Use a supplied model upstream, such as a local integration fixture.
    pub fn at(
        cx: &Cx,
        provider: Provider,
        engine: Arc<dyn Engine>,
        origin: http::Uri,
    ) -> fictionet::Result<Self> {
        Ok(Self {
            cx: cx.clone(),
            provider,
            origin,
            engine,
            sessions: Arc::default(),
        })
    }
}

impl httpd::Handler for SignedIn {
    fn call(&self, request: Request<Body>, exchange: &mut httpd::Exchange<'_>) -> httpd::Reply {
        let (value, bearer) = if let Some(value) = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
        {
            (value, true)
        } else if let Some(value) = request
            .headers()
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
        {
            (value, false)
        } else {
            return httpd::Reply::Now(self.provider.error(
                401,
                "authentication_error",
                "Sign in to the provider first.",
            ));
        };
        let key = format!("{bearer}:{value}");
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        let model = if let Some(model) = sessions.get(&key) {
            model.clone()
        } else {
            let credential = match Secret::new("guest model credential", value.to_owned()) {
                Ok(real) => Credential {
                    real,
                    placeholder: value.to_owned(),
                    oauth: None,
                    bearer,
                },
                Err(error) => {
                    return httpd::Reply::Later(Box::new(move |_| {
                        Box::pin(async move { Err(error) })
                    }));
                }
            };
            let model = match Model::at(&self.cx, self.provider, credential, self.origin.clone()) {
                Ok(model) => model.search(self.engine.clone()),
                Err(error) => {
                    return httpd::Reply::Later(Box::new(move |_| {
                        Box::pin(async move { Err(error) })
                    }));
                }
            };
            if sessions.len() >= 64 {
                sessions.clear();
            }
            sessions.insert(key, model.clone());
            model
        };
        drop(sessions);
        model.call(request, exchange)
    }
}
