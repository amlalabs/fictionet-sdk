use super::{
    Body, Fields,
    httpd::{Answer, UpgradeHandler},
};
use http::StatusCode;
use std::any::Any;
use std::sync::Arc;

/// One world-owned record retained for delivery observation.
#[derive(Clone)]
pub struct Facts(Arc<dyn Any + Send + Sync>);

impl Facts {
    /// Keeps a typed record. Construct once and clone when facts are shared.
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Arc::new(value))
    }
    /// Borrows the world's record with its original type.
    pub fn get<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref()
    }
}

/// A handler's response, with explicit protocol and observation metadata.
pub struct Response {
    /// HTTP status.
    pub status: StatusCode,
    /// Ordered response fields.
    pub fields: Fields,
    /// The response body.
    pub body: Body,
    /// Work to run after handing the HTTP connection over.
    pub upgrade: Option<UpgradeHandler>,
    /// A virtual host's built-in answer, when routing generated the response.
    pub answer: Option<Answer>,
    /// World-owned facts retained for observation.
    pub facts: Option<Facts>,
}

impl Response {
    /// An OK response with no fields or metadata.
    pub fn new(body: Body) -> Self {
        Self {
            status: StatusCode::OK,
            fields: Fields::default(),
            body,
            upgrade: None,
            answer: None,
            facts: None,
        }
    }

    /// Explicitly allocates field records from an external HTTP response.
    /// Only the named metadata types cross this boundary.
    pub fn from_http(response: http::Response<Body>) -> Self {
        let (mut parts, body) = response.into_parts();
        Self {
            status: parts.status,
            fields: Fields::new(
                parts
                    .headers
                    .iter()
                    .map(|(n, v)| (n.as_str(), v.as_bytes())),
            ),
            body,
            upgrade: parts.extensions.remove::<UpgradeHandler>(),
            answer: parts.extensions.remove::<Answer>(),
            facts: parts.extensions.remove::<Facts>(),
        }
    }

    pub(crate) fn observed(&self) -> ObservedResponse {
        ObservedResponse {
            status: self.status,
            fields: self.fields.clone(),
            answer: self.answer,
            facts: self.facts.clone(),
        }
    }
}

/// A response's metadata retained until delivery completes.
#[derive(Clone)]
pub struct ObservedResponse {
    /// Selected HTTP status.
    pub status: StatusCode,
    /// Selected response fields.
    pub fields: Fields,
    /// Built-in routing answer.
    pub answer: Option<Answer>,
    /// The world's record.
    pub facts: Option<Facts>,
}
