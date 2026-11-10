//! Random access replay of record compressed WARC archives, without unpacking.

use bytes::Bytes;
use fictionet::stdlib::codec::{Stream, finish, pump};
use fictionet::stdlib::protocols::http1::{BodyEvents, Event, Framing};
use flate2::bufread::GzDecoder;
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{self, BufRead, BufReader, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    file: PathBuf,
    offset: u64,
    length: u64,
    refers: Option<String>,
    captured: Option<String>,
}

/// An in memory URL index. Payloads stay in the original archives.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Archive {
    urls: HashMap<String, Record>,
    ids: HashMap<String, Record>,
}

/// The original HTTP response, with transport framing removed.
#[derive(Clone, Debug)]
pub struct Response {
    /// Stored HTTP status, including redirects and errors.
    pub status: StatusCode,
    /// Stored HTTP headers. Content length is recalculated after dechunking.
    pub headers: HeaderMap,
    /// Stored representation, still content encoded if the server encoded it.
    pub body: Bytes,
}

impl Response {
    /// Decode the complete stored representation.
    pub fn decoded(&self) -> io::Result<Vec<u8>> {
        let mut reader: Box<dyn Read + '_> = match self
            .headers
            .get(http::header::CONTENT_ENCODING)
            .and_then(|v| v.to_str().ok())
        {
            None | Some("identity") => Box::new(self.body.as_ref()),
            Some("gzip") => Box::new(flate2::read::GzDecoder::new(self.body.as_ref())),
            Some("deflate") => Box::new(flate2::read::ZlibDecoder::new(self.body.as_ref())),
            Some("br") => Box::new(brotli::Decompressor::new(self.body.as_ref(), 4096)),
            Some("zstd") => Box::new(zstd::stream::read::Decoder::new(self.body.as_ref())?),
            Some(encoding) => {
                return Err(invalid(format!("unsupported content encoding {encoding}")));
            }
        };
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Ok(bytes)
    }
}

fn invalid(message: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

fn split(bytes: &[u8]) -> io::Result<(&[u8], &[u8])> {
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| invalid("missing header terminator"))?;
    Ok((&bytes[..end], &bytes[end + 4..]))
}

fn parse(bytes: &[u8]) -> io::Result<&[u8]> {
    let (head, body) = split(bytes)?;
    let fields = fields(head)?;
    let length = block_length(&fields)?;
    let block = body
        .get(..length)
        .ok_or_else(|| invalid("truncated WARC block"))?;
    Ok(block)
}

/// A record's named fields, by lowercase name.
pub(crate) type Fields = HashMap<String, String>;

fn fields(head: &[u8]) -> io::Result<HashMap<String, String>> {
    let head = std::str::from_utf8(head).map_err(invalid)?;
    if !head.starts_with("WARC/1.") {
        return Err(invalid("not a WARC record"));
    }
    Ok(head
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.to_ascii_lowercase(), value.trim().to_owned()))
        .collect())
}

fn block_length(fields: &HashMap<String, String>) -> io::Result<usize> {
    fields
        .get("content-length")
        .ok_or_else(|| invalid("missing WARC content length"))?
        .parse::<usize>()
        .map_err(invalid)
}

/// Reads the one record of a gzip member: its header fields, by lowercase
/// name, checking that its block is all there.
fn read_record(reader: impl Read) -> io::Result<Fields> {
    let mut reader = BufReader::new(reader);
    let mut head = Vec::new();
    loop {
        let count = reader.read_until(b'\n', &mut head)?;
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if count == 0 {
            return Err(invalid("truncated WARC headers"));
        }
    }
    let fields = fields(&head[..head.len() - 4])?;
    let length = block_length(&fields)?;
    let remaining = io::copy(&mut reader, &mut io::sink())? as usize;
    if remaining < length {
        return Err(invalid("truncated WARC block"));
    }
    Ok(fields)
}

/// One record of an archive file, as [`each_record`] reads it.
pub(crate) struct Stored {
    /// The header fields, by lowercase name.
    pub(crate) fields: Fields,
    /// Where the record's gzip member starts in the file.
    pub(crate) offset: u64,
    /// The member's compressed length.
    pub(crate) length: u64,
}

/// Reads every record of the record-at-a-time compressed archive `file`
/// in order.
pub(crate) fn each_record(
    file: &Path,
    mut visit: impl FnMut(Stored) -> io::Result<()>,
) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(file)?);
    while !reader.fill_buf()?.is_empty() {
        let offset = reader.stream_position()?;
        let fields = read_record(GzDecoder::new(&mut reader))?;
        let length = reader.stream_position()? - offset;
        visit(Stored {
            fields,
            offset,
            length,
        })?;
    }
    Ok(())
}

/// A `WARC-Date` value for `at`: UTC, to the second (WARC 1.1 §5.4).
pub(crate) fn date(at: time::OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        at.year(),
        at.month() as u8,
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

/// Where [`append_record`] put a record.
pub(crate) struct Appended {
    /// Where its gzip member starts in the file.
    pub(crate) offset: u64,
    /// The member's compressed length.
    pub(crate) length: u64,
}

/// Appends one record to the archive at `path` as a gzip member of its
/// own, the way record-at-a-time compressed archives hold records (WARC
/// 1.1 Annex D). `fields` are the named fields after the version line;
/// this adds `WARC-Record-ID` and `Content-Length`. A failed write is cut
/// off again, so the file never ends in half a record. Callers serialize
/// writes to each file.
pub(crate) fn append_record(
    path: &Path,
    fields: &[(&str, &str)],
    block: &[u8],
) -> io::Result<Appended> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let offset = file.metadata()?.len();
    let id = format!(
        "<urn:fictionet:{}:{}:{offset}>",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    let written = (|| {
        let mut member = flate2::write::GzEncoder::new(&mut file, flate2::Compression::default());
        member.write_all(b"WARC/1.1\r\n")?;
        for (name, value) in fields {
            write!(member, "{name}: {value}\r\n")?;
        }
        write!(
            member,
            "WARC-Record-ID: {id}\r\nContent-Length: {}\r\n\r\n",
            block.len()
        )?;
        member.write_all(block)?;
        member.write_all(b"\r\n\r\n")?;
        member.finish()?.flush()
    })();
    if let Err(error) = written {
        file.set_len(offset)?;
        return Err(error);
    }
    Ok(Appended {
        offset,
        length: file.metadata()?.len() - offset,
    })
}

/// The archive files in `root`, oldest first by modification time, with
/// ties broken by path, so a later capture replaces an earlier one.
fn archive_files(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut files = std::fs::read_dir(root)?
        .map(|entry| entry.map(|e| e.path()))
        .collect::<io::Result<Vec<_>>>()?;
    files.retain(|p| p.to_string_lossy().ends_with(".warc.gz"));
    let mut files = files
        .into_iter()
        .map(|path| {
            let path = std::fs::canonicalize(path)?;
            let modified = path.metadata()?.modified()?;
            Ok((modified, path))
        })
        .collect::<io::Result<Vec<_>>>()?;
    files.sort();
    Ok(files.into_iter().map(|(_, path)| path).collect())
}

/// Canonical URL key: fragments never go to an HTTP server.
pub fn key(url: &str) -> Option<String> {
    let mut url = url::Url::parse(url.trim_start_matches('<').trim_end_matches('>')).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    url.set_fragment(None);
    Some(url.into())
}

impl Archive {
    /// Append one record compressed HTTP response and publish it for replay.
    /// Callers serialize writes to each file. Failed writes are rolled back.
    pub fn append(&mut self, path: &Path, url: &str, response: &Response) -> io::Result<()> {
        let url = key(url).ok_or_else(|| invalid("not an HTTP URL"))?;
        let mut block = format!("HTTP/1.1 {}\r\n", response.status).into_bytes();
        for (name, value) in &response.headers {
            if name != http::header::TRANSFER_ENCODING && name != http::header::CONTENT_LENGTH {
                write!(block, "{name}: ")?;
                block.extend_from_slice(value.as_bytes());
                block.extend_from_slice(b"\r\n");
            }
        }
        write!(block, "Content-Length: {}\r\n\r\n", response.body.len())?;
        block.extend_from_slice(&response.body);
        let date = date(time::OffsetDateTime::now_utc());
        let appended = append_record(
            path,
            &[
                ("WARC-Type", "response"),
                ("WARC-Target-URI", &url),
                ("WARC-Date", &date),
                ("Content-Type", "application/http; msgtype=response"),
            ],
            &block,
        )?;
        self.urls.insert(
            url,
            Record {
                file: std::fs::canonicalize(path)?,
                offset: appended.offset,
                length: appended.length,
                refers: None,
                captured: Some(date),
            },
        );
        Ok(())
    }

    /// Scan every gzip member once, retaining only URL and record locations.
    /// Revisit references are resolved after all archives have been scanned.
    pub fn open(files: impl IntoIterator<Item = PathBuf>) -> io::Result<Self> {
        let mut archive = Self::default();
        for file in files {
            let file = std::fs::canonicalize(file)?;
            each_record(&file, |stored| {
                let fields = stored.fields;
                if !matches!(
                    fields.get("warc-type").map(String::as_str),
                    Some("response" | "revisit")
                ) {
                    return Ok(());
                }
                let url = fields
                    .get("warc-target-uri")
                    .and_then(|url| key(url))
                    .ok_or_else(|| invalid("response without HTTP target URI"))?;
                let record = Record {
                    file: file.clone(),
                    offset: stored.offset,
                    length: stored.length,
                    captured: fields.get("warc-date").cloned(),
                    refers: fields
                        .get("warc-refers-to")
                        .or_else(|| fields.get("warc-refers-to-target-uri"))
                        .cloned(),
                };
                if let Some(id) = fields.get("warc-record-id") {
                    archive.ids.insert(id.clone(), record.clone());
                }
                archive.urls.insert(url, record);
                Ok(())
            })?;
        }
        Ok(archive)
    }

    /// Add later captures. Their records replace earlier records for the same URL.
    pub fn extend(&mut self, later: Archive) {
        self.urls.extend(later.urls);
        self.ids.extend(later.ids);
    }

    /// Open immutable captures in publication order, with stable path ties.
    pub fn directory(root: &Path) -> io::Result<Self> {
        let files = archive_files(&Self::directory_root(root)?)?;
        if files.is_empty() {
            return Err(invalid("no WARC archives"));
        }
        Self::open(files)
    }

    /// Resolve a published corpus once so its immutable paths stay stable.
    pub fn directory_root(root: &Path) -> io::Result<PathBuf> {
        if root.join("current").try_exists()? {
            std::fs::canonicalize(root.join("current"))
        } else {
            std::fs::canonicalize(root)
        }
    }

    /// URLs available for replay, including assets, redirects and errors.
    pub fn urls(&self) -> impl Iterator<Item = &str> {
        self.urls.keys().map(String::as_str)
    }

    /// Whether a URL belongs to this corpus.
    pub fn contains(&self, url: &str) -> bool {
        key(url).is_some_and(|key| self.urls.contains_key(&key))
    }

    /// Every record's WARC capture time the archive supplied.
    pub fn capture_times(&self) -> impl Iterator<Item = &str> {
        self.urls
            .values()
            .filter_map(|record| record.captured.as_deref())
    }

    /// The record's WARC capture time, when the archive supplied one.
    pub fn captured(&self, url: &str) -> Option<&str> {
        self.urls
            .get(&key(url)?)
            .and_then(|record| record.captured.as_deref())
    }

    /// Seek and decompress only the requested record and any revisit payload.
    pub fn get(&self, url: &str) -> io::Result<Option<Response>> {
        self.resolve(url, &mut HashSet::new())
            .map_err(|error| io::Error::new(error.kind(), format!("{url}: {error}")))
    }

    fn resolve(&self, url: &str, seen: &mut HashSet<String>) -> io::Result<Option<Response>> {
        let url = key(url).unwrap_or_else(|| url.to_owned());
        let Some(record) = self.urls.get(&url).or_else(|| self.ids.get(&url)) else {
            return Ok(None);
        };
        if !seen.insert(format!("{}:{}", record.file.display(), record.offset)) {
            return Err(invalid("cyclic revisit"));
        }
        let mut file = File::open(&record.file)?;
        file.seek(SeekFrom::Start(record.offset))?;
        let mut bytes = Vec::new();
        flate2::read::GzDecoder::new(file.take(record.length)).read_to_end(&mut bytes)?;
        let mut response = http_response(parse(&bytes)?)?;
        if let Some(reference) = &record.refers {
            let original = self
                .resolve(reference, seen)?
                .ok_or_else(|| invalid("missing revisit payload"))?;
            response.body = original.body;
        }
        response.headers.remove(http::header::TRANSFER_ENCODING);
        response.headers.insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from(response.body.len()),
        );
        Ok(Some(response))
    }
}

fn http_response(block: &[u8]) -> io::Result<Response> {
    // httparse fills a caller-sized header table; grow it until every header fits.
    let mut count = 64;
    let mut headers = loop {
        let mut headers = vec![httparse::EMPTY_HEADER; count];
        match httparse::Response::new(&mut headers).parse(block) {
            Err(httparse::Error::TooManyHeaders) => count *= 2,
            _ => break vec![httparse::EMPTY_HEADER; count],
        }
    };
    let mut parsed = httparse::Response::new(&mut headers);
    let offset = match parsed.parse(block).map_err(invalid)? {
        httparse::Status::Complete(offset) => offset,
        httparse::Status::Partial => return Err(invalid("truncated HTTP response")),
    };
    let status = StatusCode::from_u16(parsed.code.ok_or_else(|| invalid("missing status"))?)
        .map_err(invalid)?;
    let mut headers = HeaderMap::new();
    for header in parsed.headers {
        headers.append(
            HeaderName::from_bytes(header.name.as_bytes()).map_err(invalid)?,
            HeaderValue::from_bytes(header.value).map_err(invalid)?,
        );
    }
    let mut body = block[offset..].to_vec();
    if headers
        .get(http::header::TRANSFER_ENCODING)
        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"chunked"))
    {
        body = dechunk(&body)?;
    }
    Ok(Response {
        status,
        headers,
        body: body.into(),
    })
}

/// A whole chunked body without its framing, read by the body framing the
/// server and the capture use. Archives hold what real servers sent, so
/// chunk extensions and trailers are skipped.
fn dechunk(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = Stream::new(BodyEvents::new(Framing::Chunked).skip_chunk_extras());
    let mut body = Vec::new();
    let mut done = false;
    let mut on = |event: Event<_>| match event {
        Event::Body(data) => body.extend_from_slice(&data),
        Event::Done => done = true,
        Event::Head(never) => match never {},
    };
    pump(&mut stream, bytes, &mut on).map_err(invalid)?;
    finish(&mut stream, &mut on).map_err(invalid)?;
    if !done {
        return Err(invalid("truncated chunked body"));
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_bodies_lose_their_framing_extensions_and_trailers() {
        let block = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\
            2;name=value\r\nhe\r\n3 \r\nllo\r\n0\r\nX-Sum: 1\r\n\r\n";
        let response = http_response(block).unwrap();
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, &b"hello"[..]);
    }

    #[test]
    fn a_cut_off_or_misframed_chunked_body_is_refused() {
        for body in [
            &b"5\r\nhel"[..],
            b"2\r\nhe\r\n0\r\n",
            b"2\r\nhex\r\n0\r\n\r\n",
            b"zz\r\nhe\r\n0\r\n\r\n",
        ] {
            let mut block = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
            block.extend_from_slice(body);
            assert!(http_response(&block).is_err(), "{body:?}");
        }
    }
}
