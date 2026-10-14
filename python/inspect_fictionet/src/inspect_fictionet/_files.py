"""The generated files: the cache directory, cache keys, atomic
publication and the proxy token."""

from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
from pathlib import Path


def _default_cache_dir() -> Path:
    from platformdirs import user_cache_dir

    return Path(user_cache_dir("inspect_fictionet"))


def _short_key(text: str) -> str:
    # A cache key, so that different configurations get different files.
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def _write_once(directory: Path, filename: str, text: str, mode: int = 0o644) -> Path:
    """Writes `text` to `directory/<key>/filename`, where the key follows
    from the text, and returns the path. Rewrites it only if it differs."""
    path = directory / _short_key(text) / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.is_file() or path.read_text() != text:
        _write_atomic(path, text, mode)
    return path


def _write_atomic(path: Path, text: str, mode: int = 0o644) -> None:
    """Writes `text` to a temporary file next to `path`, then renames it
    over `path`. A reader sees the old file or the new one, never part of
    one, and writers in other threads or processes each use their own
    temporary file."""
    tmp = _write_temp(path, text, mode)
    try:
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def _write_temp(path: Path, text: str, mode: int) -> Path:
    """Writes `text` to a new temporary file in `path`'s directory, flushed
    to disk, and returns its path."""
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(name, mode)
    except BaseException:
        os.unlink(name)
        raise
    return Path(name)


def _valid_token(text: str) -> bool:
    return len(text) == 32 and all(c in "0123456789abcdef" for c in text)


def _proxy_token(cache: Path) -> str:
    """The proxy token: made once per cache directory, then reused, so the
    compose file stays the same across runs.

    The token is written in full to a temporary file first, then linked to
    `proxy-token`. The link fails if the file is already there, so the
    first process to publish its token wins, and every process reads a
    complete token. A file that does not hold a token (left by an older
    version, or edited by hand) is an error: replacing it here could race
    with another process doing the same, and give the two different
    tokens."""
    path = cache / "proxy-token"
    cache.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        tmp = _write_temp(path, secrets.token_hex(16) + "\n", 0o600)
        try:
            os.link(tmp, path)
        except FileExistsError:  # another process published its token first
            pass
        finally:
            tmp.unlink()
    token = path.read_text().strip()
    if not _valid_token(token):
        raise RuntimeError(f"{path} does not hold a proxy token (32 hex digits); remove it and run again")
    return token
