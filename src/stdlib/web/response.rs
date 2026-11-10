use super::{
    Body, Fields,
    httpd::{Answer, UpgradeHandler},
};
use fictionet::stdlib::protocols::fields::record_size;
use fictionet::{Budget, Chunk};
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
            fields: Fields::from(&parts.headers),
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

impl From<&http::HeaderMap> for Fields {
    /// The map's fields, in its order, in one block of exactly their size,
    /// allocated here and paid for by no budget until
    /// [`repay`](Fields::repay) moves it to one.
    fn from(map: &http::HeaderMap) -> Fields {
        let size = map
            .iter()
            .try_fold(0usize, |size, (name, value)| {
                size.checked_add(record_size(name.as_str().len(), value.len())?)
            })
            .expect("a header map's fields fit a record");
        let mut fields =
            Fields::in_block(Chunk::block(&Budget::unlimited(), 0, size).expect("unlimited"));
        for (name, value) in map {
            let written = fields.push_in_place(name.as_str().as_bytes(), value.as_bytes());
            assert!(written, "the block was sized for every field");
        }
        fields
    }
}
