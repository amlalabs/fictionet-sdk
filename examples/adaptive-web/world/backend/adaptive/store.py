"""Everything the world has said, on disk, under one directory per seed.

    pages/<host>/<segments...>/@page.json      one page: what was served, and why
    pages/<host>/<segments...>/@mentions.json  what pointed at that URL before it
                                               existed: search results, links
    pages/<host>/@site.json                    the host's name, navigation, footer
    searches/<query>/@search.json              one result list, shared by every engine
    @cast.json                                 the people pages name, made once
    claims.jsonl                               every page's stated claims, in order
    generations.jsonl                          every generator call: inputs, output, time

Paths come from the URL itself, so a person can find a page by its URL. Each
path segment is percent-encoded on its own and becomes a directory. An empty
segment (a trailing slash) is `%`. The query is one more directory that
starts with `?`. A segment longer than 180 characters is split, and the
directories after the first start with `+`. Percent-encoding never makes a
name that starts with `%` alone, `?`, `+` or `@`, so the store's own files
(`@...`) and the marks never collide with a URL's segments.

Every write goes to a temporary file first and is renamed into place, so a
reader never sees half a page. Next to a file that is made once there is a
lock file (`@page.lock`, `@search.lock`, `@site.lock`, `@mentions.lock`, `@cast.lock`).
"""
from __future__ import annotations

import fcntl
import json
import os
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from urllib.parse import quote

SAFE = "-._~!$&'(),;=:"
CHUNK = 180


def _chunks(name: str) -> list[str]:
    parts = [name[i:i + CHUNK] for i in range(0, len(name), CHUNK)] or [name]
    return [parts[0]] + ["+" + p for p in parts[1:]]


def _name(seg: str) -> str:
    """One path segment as a directory name. `.` and `..` are encoded too."""
    if not seg:
        return "%"
    name = quote(seg, safe=SAFE)
    return name.replace(".", "%2E") if set(name) == {"."} else name


def url_parts(target: str) -> list[str]:
    """The directories for `path?query`, under the host's directory."""
    path, sep, query = target.partition("?")
    out: list[str] = []
    if path not in ("", "/"):
        for seg in path.lstrip("/").split("/"):
            out += _chunks(_name(seg))
    if sep:
        out += _chunks("?" + quote(query, safe=SAFE))
    return out


def query_dir(query: str) -> str:
    return "/".join(_chunks(_name(query)))


class Store:
    """The files of one seed's world. Safe to share between threads and
    between processes: whatever is made once is made under a lock (`flock`
    on a `@...lock` file next to it), so the first maker writes it and any
    other waits, then reads what the first wrote."""

    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)

    # --- paths ---------------------------------------------------------
    def page_dir(self, host: str, target: str) -> Path:
        return self.root.joinpath("pages", _name(host), *url_parts(target))

    def host_dir(self, host: str) -> Path:
        return self.root / "pages" / _name(host)

    def search_dir(self, key: str) -> Path:
        return self.root / "searches" / query_dir(key)

    # --- files ---------------------------------------------------------
    @staticmethod
    @contextmanager
    def _locked(path: Path) -> Iterator[None]:
        """Holds an exclusive flock on `path` while the block runs. Each call
        opens the file anew, so the lock also holds between threads."""
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)

    @staticmethod
    def _read(path: Path) -> Any:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return None

    @staticmethod
    def _write(path: Path, value: Any) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(value, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, path)

    def _append(self, name: str, value: Any) -> None:
        # One write of one line to a file opened for appending: lines from
        # several writers do not mix.
        with open(self.root / name, "a", encoding="utf-8") as f:
            f.write(json.dumps(value, ensure_ascii=False) + "\n")

    def _once(self, path: Path, make: Callable[[], dict]) -> tuple[dict, bool]:
        """The record at `path`, or `make()`'s, written there. Returns it and
        whether this call made it."""
        record = self._read(path)
        if record is not None:
            return record, False
        with self._locked(path.with_name(path.stem + ".lock")):
            record = self._read(path)
            if record is not None:
                return record, False
            record = make()
            self._write(path, record)
            return record, True

    # --- pages ---------------------------------------------------------
    def page(self, host: str, target: str) -> dict | None:
        return self._read(self.page_dir(host, target) / "@page.json")

    def page_once(self, host: str, target: str, make: Callable[[], dict]) -> tuple[dict, bool]:
        """The stored page, or the one `make()` returns, stored. One caller
        makes it; the others wait for it. Returns the page and whether this
        call made it."""
        record, made = self._once(self.page_dir(host, target) / "@page.json", make)
        if made:
            for claim in record.get("claims", []):
                self._append("claims.jsonl", {"url": record["url"], "claim": claim})
        return record, made

    def pages(self, host: str = "") -> list[dict]:
        """Every stored page (or every page of `host`), oldest first: url,
        title, description, status, claims."""
        base = self.host_dir(host) if host else self.root / "pages"
        if not base.is_dir():
            return []
        out = []
        for p in base.rglob("@page.json"):
            r = self._read(p) or {}
            out.append({"url": r.get("url"), "title": r.get("title"), "description": r.get("description", ""),
                        "status": r.get("status"), "claims": r.get("claims", [])[:6], "created": r.get("created", 0)})
        out.sort(key=lambda r: r["created"])
        return out

    def mentions(self, host: str, target: str) -> list[dict]:
        return self._read(self.page_dir(host, target) / "@mentions.json") or []

    def add_mention(self, host: str, target: str, mention: dict) -> None:
        path = self.page_dir(host, target) / "@mentions.json"
        with self._locked(path.with_name("@mentions.lock")):
            current = self._read(path) or []
            if mention not in current:
                self._write(path, current + [mention])

    def site(self, host: str) -> dict | None:
        return self._read(self.host_dir(host) / "@site.json")

    def site_once(self, host: str, profile: dict) -> dict:
        """The host's layout: the first one written for it. A new one gets
        `style`, the number of hosts that had a layout before it."""
        def make() -> dict:
            pages = self.root / "pages"
            return dict(profile, style=len(list(pages.glob("*/@site.json"))))
        return self._once(self.host_dir(host) / "@site.json", make)[0]

    # --- the cast ------------------------------------------------------
    def cast_once(self, make: Callable[[], dict]) -> dict:
        """The people the world names, made once (`@cast.json`)."""
        return self._once(self.root / "@cast.json", make)[0]

    # --- searches ------------------------------------------------------
    def search(self, key: str) -> dict | None:
        return self._read(self.search_dir(key) / "@search.json")

    def search_once(self, key: str, make: Callable[[], dict]) -> tuple[dict, bool]:
        return self._once(self.search_dir(key) / "@search.json", make)

    # --- logs ----------------------------------------------------------
    def recent_claims(self, limit: int = 40) -> list[dict]:
        try:
            lines = (self.root / "claims.jsonl").read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        return [json.loads(x) for x in lines[-limit:] if x.strip()]

    def log_generation(self, entry: dict) -> None:
        self._append("generations.jsonl", entry)
