//! Use the active world connection for host-side page generation.

use super::*;

pub(super) struct ProviderTransport(pub Provider);

impl Transport for ProviderTransport {
    fn post<'a>(
        &'a self,
        cx: &'a Cx,
        headers: Vec<(&'static str, String)>,
        body: Vec<u8>,
    ) -> fictionet_extras::models::Post<'a> {
        Box::pin(async move {
            fictionet_extras::models::Https::new(cx, self.0.into())
                .map_err(|e| e.to_string())?
                .post(cx, headers, body)
                .await
        })
    }
}
