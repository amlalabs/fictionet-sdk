"""The adaptive web's pages, served on 127.0.0.1 inside the world container.

The Rust world (world/src/main.rs) owns the network: DNS for any name,
addresses, a certificate for each host, TLS and HTTP. For every request
that reaches a site it asks this server for the page, with the site's host
in the Host header. The answer carries one extra header, X-Adaptive-Meta,
with what the log records (percent-encoded JSON). The world takes it off
before the agent sees the response.

This server listens only on 127.0.0.1 in the world container's network
namespace. The agent's sandbox is in another namespace and cannot reach it.

Usage: python3 backend.py PORT

Environment:
  ADAPTIVE_WEB_SEED       seed name (in seeds/) or path. Required.
  ADAPTIVE_WEB_GENERATOR  stub (default), anthropic, or replay
  ADAPTIVE_WEB_MODEL      model for anthropic (default claude-haiku-4-5-20251001)
  ADAPTIVE_WEB_STORE      where pages are kept (default /var/lib/adaptive-web);
                          each seed gets its own directory under it
  ADAPTIVE_WEB_PREFETCH   pages to make ahead from each new result list
                          (default 3 with anthropic, else 0)
  ADAPTIVE_WEB_SEEDS      the seeds directory (default ../../seeds, else /app/seeds)
  ANTHROPIC_API_KEY       the API key, for anthropic only. Never logged.

When it is listening, it prints one line of JSON to stdout, which the world
waits for: the seed, the generator, the store, and the fixed addresses.
"""
from __future__ import annotations

import json
import os
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote

from adaptive import model, seed as seeds
from adaptive.store import Store
from adaptive.world import World, decode_form

# The search engines answer at their real addresses.
ENGINE_ADDRESSES = {
    "www.google.com": "142.250.180.4",
    "google.com": "142.250.180.14",
    "html.duckduckgo.com": "52.142.124.215",
    "duckduckgo.com": "52.142.124.215",
    "lite.duckduckgo.com": "52.142.124.215",
    "www.bing.com": "150.171.27.10",
    "bing.com": "150.171.28.10",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""
    world: World

    def log_message(self, *args):
        pass

    def _serve(self, method: str, form: dict | None = None):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        started = time.monotonic()
        try:
            r = self.world.handle(method, host, self.path, form)
        except Exception as err:  # noqa: BLE001 - the agent sees a 503, the log sees why
            traceback.print_exc()
            body = b"<html><head><title>503 Service Temporarily Unavailable</title></head><body><center><h1>503 Service Temporarily Unavailable</h1></center><hr><center>nginx</center></body></html>"
            self._send(503, "text/html", body, {}, {"kind": "error", "cache": "none", "error": str(err)[:300]}, method)
            return
        r.meta["serve_ms"] = round((time.monotonic() - started) * 1000)
        self._send(r.status, r.content_type, r.body, r.headers, r.meta, method)

    def _send(self, status, ctype, body, headers, meta, method):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "private, max-age=0")
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("X-Adaptive-Meta", quote(json.dumps(meta, ensure_ascii=False), safe=""))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._serve("GET")

    def do_HEAD(self):
        self._serve("HEAD")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        data = self.rfile.read(min(n, 1 << 20)) if n else b""
        form = decode_form(data) if "form-urlencoded" in (self.headers.get("Content-Type") or "") else None
        self._serve("POST", form)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


def main() -> int:
    port = int(sys.argv[1])
    here = Path(__file__).resolve().parent
    seeds_dir = Path(os.environ.get("ADAPTIVE_WEB_SEEDS") or (here.parents[1] / "seeds"))
    if not seeds_dir.is_dir():
        seeds_dir = Path("/app/seeds")
    name = os.environ.get("ADAPTIVE_WEB_SEED", "")
    if not name:
        print("ADAPTIVE_WEB_SEED is not set", file=sys.stderr)
        return 2
    seed = seeds.load(seeds.find(name, seeds_dir))
    generator = os.environ.get("ADAPTIVE_WEB_GENERATOR", "stub")
    if generator not in ("stub", "anthropic", "replay"):
        print(f"ADAPTIVE_WEB_GENERATOR must be stub, anthropic or replay, not {generator!r}", file=sys.stderr)
        return 2
    model_name = os.environ.get("ADAPTIVE_WEB_MODEL") or model.DEFAULT_MODEL
    prefetch = int(os.environ.get("ADAPTIVE_WEB_PREFETCH") or (3 if generator == "anthropic" else 0))
    store = Store(Path(os.environ.get("ADAPTIVE_WEB_STORE", "/var/lib/adaptive-web")) / seed.name)
    try:
        world = World(seed, store, generator, model_name, prefetch)
    except model.ModelError as err:
        print(f"cannot start the {generator} generator: {err}", file=sys.stderr)
        return 2
    Handler.world = world
    server = Server(("127.0.0.1", port), Handler)
    addresses = {h: {"addr": a, "why": "search engine"} for h, a in ENGINE_ADDRESSES.items()}
    addresses |= {h: {"addr": a, "why": "seed"} for h, a in seed.addresses.items()}
    print(json.dumps({
        "seed": seed.name, "date": seed.date, "question": seed.question, "generator": generator,
        "model": world.model_name, "prefetch": prefetch, "store": str(store.root.resolve()),
        "addresses": addresses, "fixed": [f.url for f in seed.fixed],
    }), flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
