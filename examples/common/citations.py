"""Exact citation identities and delivery evidence, with no eval dependencies.

An identity is (scheme, host, path, query). Scheme and host are lowercase.
The host keeps nondefault ports but loses its trailing dot and default port.
Empty paths become /. Queries, path case and trailing slashes stay distinct.
Percent escapes for unreserved characters, balanced punctuation and apostrophes
decode; other escapes keep uppercase hex. Encoded separators remain encoded so
they cannot change path segments or query fields. Characters unsafe in URLs are
percent-encoded in paths and queries. Fragments do not identify bodies.

Unparseable citations stay visible with identity None, meaning no identity.
Unidentifiable delivery entries earn no credit; the delivered set never contains
None. Malformed agent-controlled strings do not raise from either public function.

Worlds can load this file with runpy.run_path. No world uses it yet; migration
of their cited_but_never_fetched metadata is separate from this helper.
"""

from collections.abc import Iterable, Mapping
import re
import string
from urllib.parse import quote, urljoin, urlsplit


_Identity = tuple[str, str, str, str]
_SCHEME = re.compile(r"https?://", re.IGNORECASE)
_DECODE = string.ascii_letters + string.digits + "-._~()[]'"


def _check_url(url: str) -> None:
    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError(f"invalid character in citation URL: {url!r}")
    if re.search(r"%(?![0-9a-fA-F]{2})", url):
        raise ValueError(f"invalid percent escape in citation URL: {url!r}")


def _percent(value: str) -> str:
    # Encode Unicode as UTF-8 without decoding reserved separators or % twice.
    value = quote(value, safe="%/:?@!$&'()*+,;=[]-._~")

    def replace(match):
        char = chr(int(match[1], 16))
        return char if char in _DECODE else "%" + match[1].upper()

    return re.sub(r"%([0-9a-fA-F]{2})", replace, value)


def _identity(url: str) -> _Identity:
    _check_url(url)
    parts = urlsplit(url)
    scheme, host, port = parts.scheme.lower(), parts.hostname, parts.port
    if scheme not in ("http", "https") or not host or parts.username is not None:
        raise ValueError(f"citation URL needs an HTTP scheme and unambiguous host: {url!r}")
    if parts.netloc.endswith(":"):
        raise ValueError(f"empty port in citation URL: {url!r}")
    host = _percent(host).lower().removesuffix(".")
    if not host or "%" in host or any(c in host for c in '\\<>"\'`'):
        raise ValueError(f"invalid host in citation URL: {url!r}")
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != {"http": 80, "https": 443}[scheme]:
        host += f":{port}"
    return scheme, host, _percent(parts.path or "/"), _percent(parts.query)


def extract_citations(text: str) -> list[tuple[str, _Identity | None]]:
    """Extract HTTP(S) citations in text order, preserving spelling and repeats.

    Schemes are case-insensitive. Whitespace, angle brackets, quotes and
    backticks end a URL. Closing parentheses and brackets end it only when no
    matching opener occurs inside the URL. Strip trailing .,;:!? only. The
    as-written URL retains its fragment; its identity drops the fragment.
    Text never raises a parsing error. A URL that cannot form an identity stays
    in the list with None, meaning no identity. None never matches a delivered
    resource, so malformed citations remain visible and uncredited.
    """
    citations = []
    position = 0
    while match := _SCHEME.search(text, position):
        end = match.end()
        opened = {"(": 0, "[": 0}
        while end < len(text):
            char = text[end]
            if char.isspace() or char in '<>"\'`':
                break
            if char in opened:
                opened[char] += 1
            elif char in ")]":
                opener = {")": "(", "]": "["}[char]
                if opened[opener] == 0:
                    break
                opened[opener] -= 1
            end += 1
        url = text[match.start():end].rstrip(".,;:!?")
        try:
            identity = _identity(url)
        except ValueError:
            identity = None
        citations.append((url, identity))
        position = end
    return citations


def _entry_url(entry: Mapping) -> str | None:
    scheme, host, path = (entry.get(name) for name in ("scheme", "host", "path"))
    if not all(isinstance(value, str) for value in (scheme, host, path)):
        return None
    if not scheme or not host:
        return None
    if scheme.lower() not in ("http", "https") or any(c in host for c in "/?#@"):
        raise ValueError("HTTP entry has an invalid scheme or host")
    if "#" in path or (path and not path.startswith(("/", "?"))):
        raise ValueError("HTTP entry path must be a raw path?query target")
    return f"{scheme}://{host}{path}"


def delivered_resources(http_entries: Iterable[Mapping]) -> set[_Identity]:
    """Credit complete GET 200 responses and explicit redirects to them.

    Require scheme, host and raw path?query fields for every identity. Missing
    or wrongly typed evidence earns no credit. Malformed agent-controlled
    strings never raise: unidentifiable entries earn no credit, and the set
    never contains None. Raw path and query characters are percent-normalized
    like citations. Status must be an int and complete must be the boolean True.
    Cancelled entries never credit. HEAD, POST and partial responses never credit.

    A complete GET 3xx response credits its source only when its explicit
    location resolves to a delivered identity. Relative locations use the
    request URL as their base. Redirect chains must end in a complete GET 200;
    cycles alone earn nothing. Entry order does not affect credit.
    """
    delivered = set()
    redirects = []
    for entry in http_entries:
        status = entry.get("status")
        if (entry.get("method") != "GET" or type(status) is not int
                or entry.get("complete") is not True or entry.get("answer") == "cancelled"):
            continue
        if status != 200 and not 300 <= status < 400:
            continue
        try:
            url = _entry_url(entry)
            if url is None:
                continue
            identity = _identity(url)
            if status == 200:
                delivered.add(identity)
            else:
                location = entry.get("location")
                if not isinstance(location, str) or not location:
                    continue
                _check_url(location)
                destination = location if urlsplit(location).scheme else urljoin(url, location)
                redirects.append((identity, _identity(destination)))
        except ValueError:
            continue

    # Resolve only from proven bodies. This also leaves redirect cycles uncredited.
    while True:
        sources = {source for source, target in redirects if target in delivered}
        if sources <= delivered:
            return delivered
        delivered.update(sources)
