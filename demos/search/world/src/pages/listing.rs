//! Answer every search engine from the active page source.

use super::*;

/// A result list and the scenario's edits to it.
pub(super) struct Found {
    pub search: search::Search,
    pub edits: Vec<Edit>,
}

/// The page a busy server shows when the search provider cannot answer.
pub(super) const UNAVAILABLE: &[u8] =
    b"<html><head><title>503 Service Temporarily Unavailable</title></head>\
<body><center><h1>503 Service Temporarily Unavailable</h1></center><hr><center>nginx</center>\
</body></html>";

impl Pages {
    pub(super) async fn search(
        &self,
        cx: &Cx,
        engine: Engine,
        query: &str,
        start: u64,
    ) -> Response {
        let found = match self.listing(cx, query, start, &Default::default()).await {
            Ok(found) => found,
            Err(error) => {
                let headers = vec![("Server".into(), "nginx".into())];
                return Response::new(
                    503,
                    "text/html",
                    UNAVAILABLE,
                    headers,
                    Meta::Error { error },
                );
            }
        };
        let body = search::render(engine, query, &found.search, start);
        let listing = Listing {
            engine,
            search: query.into(),
            listed: (found.search.results.iter())
                .map(|result| (result.url.clone(), result.title.clone()))
                .collect(),
            edits: found.edits,
        };
        Response::html(
            body,
            Meta::Search(Box::new(listing)),
            200,
            fictionet_extras::search::engine_server(engine),
        )
    }

    /// The result list a search shows, from the active source.
    pub(super) async fn listing(
        &self,
        cx: &Cx,
        query: &str,
        start: u64,
        domains: &fictionet_extras::models::tools::Domains,
    ) -> Result<Found, String> {
        if domains.allowed_domains.as_ref().is_some_and(Vec::is_empty) {
            return Ok(Found {
                search: search::Search {
                    total: Some(0),
                    ..Default::default()
                },
                edits: Vec::new(),
            });
        }
        match self.source() {
            Source::Copied => Ok(Found {
                search: self.copied_listing(query, start, domains)?,
                edits: Vec::new(),
            }),
            Source::Live | Source::LiveDepth => Ok(Found {
                search: self.live_listing(cx, query, start, domains).await?,
                edits: Vec::new(),
            }),
            Source::Edited => {
                let mut search = self.live_listing(cx, query, start, domains).await?;
                let editor = self.editor.as_ref().expect("Edited has an editor");
                // A list the editor cannot change is served as it is.
                let edits = match editor.results(cx, query, &mut search.results).await {
                    Ok(edits) => edits,
                    Err(error) => {
                        eprintln!("Results for {query:?} were not edited: {error}");
                        Vec::new()
                    }
                };
                Ok(Found { search, edits })
            }
        }
    }
}
