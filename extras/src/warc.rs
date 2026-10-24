//! Random access replay of record compressed WARC archives, without unpacking.

use bytes::Bytes;
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
#[derive(Debug)]
pub struct Response {
    /// Stored HTTP status, including redirects and errors.
    pub status: StatusCode,
    /// Stored HTTP headers. Content length is recalculated after dechunking.
    pub headers: HeaderMap,
    /// Stored representation, still content encoded if the server encoded it.
    pub body: Bytes,
}

impl Response {
    /// Decode the complete representation.
    pub fn decoded(&self) -> io::Result<Vec<u8>> {
        self.decode(None)
    }

    /// Decode at most `limit` bytes, rejecting larger representations rather than
    /// returning a truncated document to a parser.
    pub fn decoded_with_limit(&self, limit: usize) -> io::Result<Vec<u8>> {
        self.decode(Some(limit))
    }

    fn decode(&self, limit: Option<usize>) -> io::Result<Vec<u8>> {
        let reader: Box<dyn Read + '_> = match self
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
        match limit {
            Some(limit) => reader
                .take(limit.saturating_add(1) as u64)
                .read_to_end(&mut bytes)?,
            None => {
                let mut reader = reader;
                reader.read_to_end(&mut bytes)?
            }
        };
        if limit.is_some_and(|limit| bytes.len() > limit) {
            return Err(invalid("decoded response exceeds size limit"));
        }
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
    let length = fields
        .get("content-length")
        .ok_or_else(|| invalid("missing WARC content length"))?
        .parse::<usize>()
        .map_err(invalid)?;
    Ok(length)
}

fn scan(reader: impl Read) -> io::Result<HashMap<String, String>> {
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
        let now = time::OffsetDateTime::now_utc();
        let date = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            now.year(),
            now.month() as u8,
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let offset = file.metadata()?.len();
        let written = (|| {
            let mut member =
                flate2::write::GzEncoder::new(&mut file, flate2::Compression::default());
            write!(
                member,
                "WARC/1.1\r\nWARC-Type: response\r\nWARC-Target-URI: {url}\r\nWARC-Date: {date}\r\nWARC-Record-ID: <urn:fictionet:{}:{}:{offset}>\r\nContent-Type: application/http; msgtype=response\r\nContent-Length: {}\r\n\r\n",
                std::process::id(),
                now.unix_timestamp_nanos(),
                block.len()
            )?;
            member.write_all(&block)?;
            member.write_all(b"\r\n\r\n")?;
            member.finish()?.flush()
        })();
        if let Err(error) = written {
            file.set_len(offset)?;
            return Err(error);
        }
        self.urls.insert(
            url,
            Record {
                file: std::fs::canonicalize(path)?,
                offset,
                length: file.metadata()?.len() - offset,
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
            let mut reader = BufReader::new(File::open(&file)?);
            while !reader.fill_buf()?.is_empty() {
                let offset = reader.stream_position()?;
                let fields = scan(GzDecoder::new(&mut reader))?;
                let length = reader.stream_position()? - offset;
                if !matches!(
                    fields.get("warc-type").map(String::as_str),
                    Some("response" | "revisit")
                ) {
                    continue;
                }
                let url = fields
                    .get("warc-target-uri")
                    .and_then(|url| key(url))
                    .ok_or_else(|| invalid("response without HTTP target URI"))?;
                let record = Record {
                    file: file.clone(),
                    offset,
                    length,
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
            }
        }
        Ok(archive)
    }

    /// Open immutable captures in publication order, with stable path ties.
    pub fn directory(root: &Path) -> io::Result<Self> {
        let root = Self::directory_root(root)?;
        let mut files = std::fs::read_dir(&root)?
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
        if files.is_empty() {
            return Err(invalid("no WARC archives"));
        }
        Self::open(files.into_iter().map(|(_, path)| path))
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

    /// The record's WARC capture time, when the archive supplied one.
    pub fn captured(&self, url: &str) -> Option<&str> {
        self.urls
            .get(&key(url)?)
            .and_then(|record| record.captured.as_deref())
    }

    /// Seek and decompress only the requested record and any revisit payload.
    pub fn get(&self, url: &str) -> io::Result<Option<Response>> {
        self.resolve(url, &mut HashSet::new())
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
    let mut headers = [httparse::EMPTY_HEADER; 256];
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
        let mut remaining = body.as_slice();
        let mut decoded = Vec::new();
        loop {
            let end = remaining
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| invalid("missing chunk size"))?;
            let size = std::str::from_utf8(&remaining[..end])
                .map_err(invalid)?
                .split(';')
                .next()
                .unwrap();
            let size = usize::from_str_radix(size.trim(), 16).map_err(invalid)?;
            remaining = &remaining[end + 2..];
            if size == 0 {
                break;
            }
            decoded.extend_from_slice(
                remaining
                    .get(..size)
                    .ok_or_else(|| invalid("truncated chunk"))?,
            );
            if remaining.get(size..size + 2) != Some(b"\r\n") {
                return Err(invalid("missing chunk terminator"));
            }
            remaining = &remaining[size + 2..];
        }
        body = decoded;
    }
    Ok(Response {
        status,
        headers,
        body: body.into(),
    })
}
