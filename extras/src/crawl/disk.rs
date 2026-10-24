//! Persistent BM25 search, with the same analyzer for documents and queries.

use crate::search;
use std::{io, path::Path};
use tantivy::{
    Index, IndexReader, IndexWriter, TantivyDocument, Term,
    collector::{Count, TopDocs},
    query::{BooleanQuery, ConstScoreQuery, Occur, Query, RegexQuery, TermQuery},
    schema::{
        Field, IndexRecordOption, STORED, STRING, Schema, TextFieldIndexing, TextOptions, Value,
    },
    snippet::SnippetGenerator,
    tokenizer::{Language, LowerCaser, SimpleTokenizer, Stemmer, TextAnalyzer},
};

#[derive(Clone, Copy)]
struct Fields {
    url: Field,
    title: Field,
    body: Field,
}

fn schema() -> (Schema, Fields) {
    let mut schema = Schema::builder();
    let text = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("english")
            .set_index_option(IndexRecordOption::WithFreqs),
    );
    let url = schema.add_text_field("url", STRING | STORED);
    let title = schema.add_text_field("title", STORED);
    let body = schema.add_text_field("body", text);
    (schema.build(), Fields { url, title, body })
}

fn analyzer(index: &Index) {
    index.tokenizers().register(
        "english",
        TextAnalyzer::builder(SimpleTokenizer::default())
            .filter(LowerCaser)
            .filter(Stemmer::new(Language::English))
            .build(),
    );
}

/// A read-only memory-mapped search index. Opening it never crawls pages.
pub struct DiskIndex {
    index: Index,
    reader: IndexReader,
    fields: Fields,
}

impl DiskIndex {
    /// Open a prepared index without reading its source documents.
    pub fn open(path: &Path) -> io::Result<Self> {
        let index = Index::open_in_dir(path).map_err(io::Error::other)?;
        let (schema, fields) = schema();
        if index.schema() != schema {
            return Err(io::Error::other("search index needs rebuilding"));
        }
        analyzer(&index);
        let reader = index.reader().map_err(io::Error::other)?;
        Ok(Self {
            index,
            reader,
            fields,
        })
    }

    /// Number of searchable documents.
    pub fn len(&self) -> u64 {
        self.reader.searcher().num_docs()
    }
    /// Whether the index contains no documents.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Source identity retained in the index commit.
    pub fn source(&self) -> io::Result<Option<String>> {
        Ok(self.index.load_metas().map_err(io::Error::other)?.payload)
    }

    /// Query text is data, never query syntax. Every matching term contributes.
    pub fn search(
        &self,
        query: &str,
        start: usize,
        limit: usize,
        mut text_for: impl FnMut(&str) -> io::Result<String>,
    ) -> io::Result<search::Search> {
        self.search_in(query, start, limit, &Default::default(), &mut text_for)
    }

    /// Apply domain restrictions before collecting scores, counts and pages.
    pub fn search_in(
        &self,
        query: &str,
        start: usize,
        limit: usize,
        domains: &crate::models::tools::Domains,
        mut text_for: impl FnMut(&str) -> io::Result<String>,
    ) -> io::Result<search::Search> {
        let mut analyzer = self
            .index
            .tokenizer_for_field(self.fields.body)
            .map_err(io::Error::other)?;
        let mut stream = analyzer.token_stream(query);
        let mut words = std::collections::BTreeSet::new();
        while stream.advance() {
            words.insert(stream.token().text.clone());
        }
        if words.is_empty() || limit == 0 {
            return Ok(search::Search {
                total: Some(0),
                ..Default::default()
            });
        }
        let mut clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();
        for word in words {
            let term = TermQuery::new(
                Term::from_field_text(self.fields.body, &word),
                IndexRecordOption::WithFreqs,
            );
            clauses.push((Occur::Should, Box::new(term)));
        }
        let mut clauses: Vec<(Occur, Box<dyn Query>)> =
            vec![(Occur::Must, Box::new(BooleanQuery::new(clauses)))];
        let domain_query = |domains: &[String]| -> io::Result<Box<dyn Query>> {
            let mut alternatives: Vec<(Occur, Box<dyn Query>)> = Vec::new();
            for domain in domains {
                let domain = regex::escape(&domain.trim_matches('.').to_ascii_lowercase());
                let pattern = format!("https?://([^/]+\\.)?{domain}(:[0-9]+)?/.*");
                alternatives.push((
                    Occur::Should,
                    Box::new(
                        RegexQuery::from_pattern(&pattern, self.fields.url)
                            .map_err(io::Error::other)?,
                    ),
                ));
            }
            Ok(Box::new(BooleanQuery::new(alternatives)))
        };
        if let Some(allowed) = &domains.allowed_domains {
            clauses.push((
                Occur::Must,
                Box::new(ConstScoreQuery::new(domain_query(allowed)?, 0.0)),
            ));
        }
        if let Some(blocked) = &domains.blocked_domains {
            clauses.push((Occur::MustNot, domain_query(blocked)?));
        }
        let query = BooleanQuery::new(clauses);
        let searcher = self.reader.searcher();
        let count = searcher.search(&query, &Count).map_err(io::Error::other)?;
        if start >= count {
            return Ok(search::Search {
                total: Some(count),
                ..Default::default()
            });
        }
        let hits = searcher
            .search(
                &query,
                &TopDocs::with_limit(limit)
                    .and_offset(start)
                    .order_by_score(),
            )
            .map_err(io::Error::other)?;
        let mut snippet = SnippetGenerator::create(&searcher, &query, self.fields.body)
            .map_err(io::Error::other)?;
        snippet.set_max_num_chars(220);
        let mut results = Vec::new();
        for (_, address) in hits {
            let document: TantivyDocument = searcher.doc(address).map_err(io::Error::other)?;
            let text = |field| {
                document
                    .get_first(field)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned()
            };
            let url = text(self.fields.url);
            let body = text_for(&url)?;
            results.push(search::Result {
                url,
                title: text(self.fields.title),
                snippet: snippet.snippet(&body).fragment().to_owned(),
                ..Default::default()
            });
        }
        Ok(search::Search {
            total: Some(count),
            results,
            ..Default::default()
        })
    }
}

/// A bounded-memory writer, used by corpus preparation rather than startup.
pub struct DiskWriter {
    writer: IndexWriter,
    fields: Fields,
}

impl DiskWriter {
    /// Update a private copy of a published index.
    pub fn open(path: &Path) -> io::Result<Self> {
        let index = Index::open_in_dir(path).map_err(io::Error::other)?;
        analyzer(&index);
        let (_, fields) = schema();
        let threads = std::thread::available_parallelism()?.get().div_ceil(2);
        let writer = index
            .writer_with_num_threads(threads, threads * 64_000_000)
            .map_err(io::Error::other)?;
        Ok(Self { writer, fields })
    }

    /// Remove an earlier document at its original URL.
    pub fn remove(&self, url: &str) {
        self.writer
            .delete_term(Term::from_field_text(self.fields.url, url));
    }

    /// Start a new index in an empty staging directory.
    pub fn create(path: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(path)?;
        let (schema, fields) = schema();
        let mut index = Index::create_in_dir(path, schema).map_err(io::Error::other)?;
        analyzer(&index);
        index.settings_mut().docstore_compression =
            tantivy::store::Compressor::Zstd(Default::default());
        let threads = std::thread::available_parallelism()?.get().div_ceil(2);
        let writer = index
            .writer_with_num_threads(threads, threads * 64_000_000)
            .map_err(io::Error::other)?;
        Ok(Self { writer, fields })
    }
    /// Index an original URL and its title and readable text.
    pub fn add(&self, url: &str, title: &str, body: &str) -> io::Result<()> {
        self.writer
            .add_document(tantivy::doc!(self.fields.url => url,
            self.fields.title => title,
            self.fields.body => title, self.fields.body => title, self.fields.body => body))
            .map_err(io::Error::other)?;
        Ok(())
    }
    /// Commit documents and finish all segment merges before publication.
    pub fn finish(mut self, source: &str) -> io::Result<()> {
        let mut commit = self.writer.prepare_commit().map_err(io::Error::other)?;
        commit.set_payload(source);
        commit.commit().map_err(io::Error::other)?;
        self.writer.wait_merging_threads().map_err(io::Error::other)
    }
}
