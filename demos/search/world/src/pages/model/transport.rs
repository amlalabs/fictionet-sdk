//! Use the active world connection for host-side page generation.

use super::*;

pub(super) struct ProviderTransport {
    provider: Provider,
    client: std::sync::Mutex<Option<fictionet_extras::models::Https>>,
    observer: std::sync::Mutex<Option<Arc<fictionet_extras::models::UpstreamObserver>>>,
}
impl ProviderTransport {
    pub(super) fn new(provider: Provider) -> Self {
        Self {
            provider,
            client: Default::default(),
            observer: Default::default(),
        }
    }
}

impl Transport for ProviderTransport {
    fn observe_upstream(&self, observer: Arc<fictionet_extras::models::UpstreamObserver>) {
        *self.observer.lock().unwrap() = Some(observer);
    }

    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> fictionet_extras::models::Post<'a> {
        Box::pin(async move {
            let client = {
                let mut cached = self.client.lock().unwrap();
                if cached.is_none() {
                    *cached = Some(
                        fictionet_extras::models::Https::new(cx, self.provider.into())
                            .map_err(|e| e.to_string())?,
                    );
                }
                cached
                    .as_ref()
                    .expect("initialized provider transport")
                    .clone()
            };
            if let Some(observer) = self.observer.lock().unwrap().clone() {
                client.observe_upstream(observer);
            }
            client.post(cx, headers, body).await
        })
    }
}
