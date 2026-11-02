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
/// name, and its block when `keep` wants it after seeing the fields.
fn read_record(
    reader: impl Read,
    keep: impl FnOnce(&Fields) -> bool,
) -> io::Result<(Fields, Option<Vec<u8>>)> {
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
    let block = if keep(&fields) {
        let mut block = vec![0; length];
        reader
            .read_exact(&mut block)
            .map_err(|_| invalid("truncated WARC block"))?;
        io::copy(&mut reader, &mut io::sink())?;
        Some(block)
    } else {
        let remaining = io::copy(&mut reader, &mut io::sink())? as usize;
        if remaining < length {
            return Err(invalid("truncated WARC block"));
        }
        None
    };
    Ok((fields, block))
}

/// One record of an archive file, as [`each_record`] reads it.
pub(crate) struct Stored {
    /// The header fields, by lowercase name.
    pub(crate) fields: Fields,
    /// The block, when the reader asked for it.
    pub(crate) block: Option<Vec<u8>>,
    /// Where the record's gzip member starts in the file.
    pub(crate) offset: u64,
    /// The member's compressed length.
    pub(crate) length: u64,
}

/// Reads every record of the record-at-a-time compressed archive `file`
/// in order, with the blocks `keep` asks for.
pub(crate) fn each_record(
    file: &Path,
    keep: impl Fn(&Fields) -> bool,
    mut visit: impl FnMut(Stored) -> io::Result<()>,
) -> io::Result<()> {
    let mut reader = BufReader::new(File::open(file)?);
    while !reader.fill_buf()?.is_empty() {
        let offset = reader.stream_position()?;
        let (fields, block) = read_record(GzDecoder::new(&mut reader), &keep)?;
        let length = reader.stream_position()? - offset;
        visit(Stored {
            fields,
            block,
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
    /// The record's `WARC-Record-ID`.
    pub(crate) id: String,
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
        id,
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
    /// DNS records (`dns:` target URIs) in the same files are left to
    /// [`dns::Replay`](crate::dns::Replay).
    pub fn open(files: impl IntoIterator<Item = PathBuf>) -> io::Result<Self> {
        let mut archive = Self::default();
        for file in files {
            let file = std::fs::canonicalize(file)?;
            each_record(
                &file,
                |_| false,
                |stored| {
                    let fields = stored.fields;
                    if !matches!(
                        fields.get("warc-type").map(String::as_str),
                        Some("response" | "revisit")
                    ) {
                        return Ok(());
                    }
                    let target = fields.get("warc-target-uri");
                    if target.is_some_and(|uri| crate::dns::is_dns_uri(uri)) {
                        return Ok(());
                    }
                    let url = target
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
                },
            )?;
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
