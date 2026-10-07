"""The seed: one Markdown file with TOML front matter between `+++` lines.

The front matter holds what must hold everywhere in the world:

    date      the world's today, YYYY-MM-DD (default: the real today)
    question  the task the eval gives the agent
    facts     sentences every page must agree with
    [[sites]] host + about: hosts the scenario is about
    [[fixed]] url + file (+ title, description, content_type): pages
              served exactly as written, in place of generated ones
    [addresses]  host = "a.b.c.d": addresses for hosts that should not
              get one from the world's pool

The Markdown body is the scenario, in plain words, for the generator.
Only the standard library is needed (tomllib, Python 3.11 and later).
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit


@dataclass
class Fixed:
    url: str
    host: str
    target: str
    file: Path
    title: str
    description: str
    content_type: str


@dataclass
class Site:
    host: str
    about: str


@dataclass
class Seed:
    name: str
    path: Path
    date: str
    question: str
    scenario: str
    facts: list[str]
    sites: list[Site] = field(default_factory=list)
    fixed: list[Fixed] = field(default_factory=list)
    addresses: dict[str, str] = field(default_factory=dict)

    def fixed_for(self, host: str, target: str) -> Fixed | None:
        for f in self.fixed:
            if f.host == host and f.target == target:
                return f
        return None

    def about(self, host: str) -> str | None:
        for s in self.sites:
            if s.host == host:
                return s.about
        return None


def target_of(url: str) -> tuple[str, str]:
    """(host, path?query) of an absolute URL, as the world keys pages."""
    u = urlsplit(url)
    target = u.path or "/"
    if u.query:
        target += "?" + u.query
    return (u.hostname or "").lower(), target


def find(name_or_path: str, seeds_dir: Path) -> Path:
    p = Path(name_or_path)
    if p.is_file():
        return p
    for candidate in (seeds_dir / name_or_path, seeds_dir / f"{name_or_path}.md"):
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"no seed named {name_or_path!r} (looked in {seeds_dir})")


def load(path: Path) -> Seed:
    text = path.read_text(encoding="utf-8")
    if not text.startswith("+++"):
        raise ValueError(f"{path}: a seed starts with +++ and TOML front matter")
    _, front, body = text.split("+++", 2)
    meta = tomllib.loads(front)
    date = str(meta.get("date") or dt.date.today().isoformat())
    dt.date.fromisoformat(date)
    fixed = []
    for f in meta.get("fixed", []):
        host, target = target_of(f["url"])
        file = (path.parent / f["file"]).resolve()
        if not file.is_file():
            raise ValueError(f"{path}: fixed page file {file} does not exist")
        fixed.append(Fixed(url=f["url"], host=host, target=target, file=file,
                           title=f.get("title", ""), description=f.get("description", ""),
                           content_type=f.get("content_type", "text/html; charset=utf-8")))
    addresses = {}
    for host, addr in meta.get("addresses", {}).items():
        ipaddress.IPv4Address(addr)
        addresses[host.lower()] = addr
    return Seed(
        name=path.stem,
        path=path,
        date=date,
        question=" ".join(str(meta.get("question", "")).split()),
        scenario=body.strip(),
        facts=[str(f) for f in meta.get("facts", [])],
        sites=[Site(host=s["host"].lower(), about=s.get("about", "")) for s in meta.get("sites", [])],
        fixed=fixed,
        addresses=addresses,
    )
