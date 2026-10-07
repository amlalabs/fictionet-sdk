"""Everything the world has said, on disk, under one directory per seed.

    pages/<host>/<segments...>/@page.json      one page: what was served, and why
    pages/<host>/<segments...>/@mentions.json  what pointed at that URL before it
                                               existed: search results, links
    pages/<host>/@site.json                    the host's name, navigation, footer
    searches/<query>/@search.json              one result list, shared by every engine
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
reader never sees half a page.
"""
from __future__ import annotations

import json
import os
import threading
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
    def __init__(self, root: Path):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self._append_lock = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}
        self._locks_lock = threading.Lock()

    # --- locking: one generation per key at a time ---------------------
    def lock(self, key: str) -> threading.Lock:
        with self._locks_lock:
            return self._locks.setdefault(key, threading.Lock())

    # --- paths ---------------------------------------------------------
    def page_dir(self, host: str, target: str) -> Path:
        return self.root.joinpath("pages", _name(host), *url_parts(target))

    def host_dir(self, host: str) -> Path:
        return self.root / "pages" / _name(host)

    # --- files ---------------------------------------------------------
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
        line = json.dumps(value, ensure_ascii=False) + "\n"
        with self._append_lock, open(self.root / name, "a", encoding="utf-8") as f:
            f.write(line)

    # --- pages ---------------------------------------------------------
    def page(self, host: str, target: str) -> dict | None:
        return self._read(self.page_dir(host, target) / "@page.json")

    def save_page(self, host: str, target: str, record: dict) -> None:
        self._write(self.page_dir(host, target) / "@page.json", record)
        for claim in record.get("claims", []):
            self._append("claims.jsonl", {"url": record["url"], "claim": claim})

    def pages_on(self, host: str, limit: int = 30) -> list[dict]:
        """Pages already served on `host`: url, title, claims. Oldest first."""
        out = []
        base = self.host_dir(host)
        if not base.is_dir():
            return out
        for p in base.rglob("@page.json"):
            r = self._read(p) or {}
            out.append({"url": r.get("url"), "title": r.get("title"), "claims": r.get("claims", [])[:6],
                        "created": r.get("created", 0)})
        out.sort(key=lambda r: r["created"])
        return out[:limit]

    def mentions(self, host: str, target: str) -> list[dict]:
        return self._read(self.page_dir(host, target) / "@mentions.json") or []

    def add_mention(self, host: str, target: str, mention: dict) -> None:
        with self.lock(f"mentions {host}{target}"):
            path = self.page_dir(host, target) / "@mentions.json"
            current = self._read(path) or []
            if mention not in current:
                current.append(mention)
                self._write(path, current)

    def site(self, host: str) -> dict | None:
        return self._read(self.host_dir(host) / "@site.json")

    def save_site_once(self, host: str, profile: dict) -> dict:
        """Keeps the first profile written for a host and returns it."""
        with self.lock(f"site {host}"):
            current = self.site(host)
            if current is not None:
                return current
            existing = len(list((self.root / "pages").glob("*/@site.json"))) if (self.root / "pages").is_dir() else 0
            profile = dict(profile, style=existing)
            self._write(self.host_dir(host) / "@site.json", profile)
            return profile

    # --- searches ------------------------------------------------------
    def search(self, query: str) -> dict | None:
        return self._read(self.root / "searches" / query_dir(query) / "@search.json")

    def save_search(self, query: str, record: dict) -> None:
        self._write(self.root / "searches" / query_dir(query) / "@search.json", record)

    # --- logs ----------------------------------------------------------
    def recent_claims(self, limit: int = 40) -> list[dict]:
        try:
            lines = (self.root / "claims.jsonl").read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        return [json.loads(x) for x in lines[-limit:] if x.strip()]

    def log_generation(self, entry: dict) -> None:
        self._append("generations.jsonl", entry)
