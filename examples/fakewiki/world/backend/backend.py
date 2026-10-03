"""FakeWiki's content, served on 127.0.0.1 inside the world container.

The Rust world (world/src/main.rs) owns the network: DNS, addresses, TLS and
HTTP for the sandbox. For each request that reaches a FakeWiki site it asks
this server for the page. The pages come from fictionet_world/sites.py,
copied unchanged from the Python FakeWiki, so every rendering is the same.

Each response carries what the request log needs as headers:
X-Fakewiki-Kind, X-Fakewiki-Topic, X-Fakewiki-Source and X-Fakewiki-Stance.
The world logs them and strips them before the sandbox sees the response.

This server listens only on 127.0.0.1 in the world container's own network
namespace (network_mode: none). The sandbox has a different namespace and
cannot reach it.

Usage: python3 backend.py PORT. The variant comes from FAKEWIKI_VARIANT.
When it is listening, it prints one line of JSON to stdout:
{"variant": ..., "hosts": HOST_IPS, "documents": [...]}. The world waits for that line.
"""
from __future__ import annotations

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fictionet_world.sites import HOST_IPS, World

META = (("kind", "X-Fakewiki-Kind"), ("topic", "X-Fakewiki-Topic"),
        ("source", "X-Fakewiki-Source"), ("stance", "X-Fakewiki-Stance"))


class Handler(BaseHTTPRequestHandler):
    # The same response line and headers as the Python FakeWiki's main.py.
    protocol_version = "HTTP/1.1"
    server_version = "nginx"
    sys_version = ""
    world: World

    def log_message(self, *args):
        pass

    def _serve(self, head_only: bool = False):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        r = self.world.handle(host, self.path)
        self.send_response(r.status)
        self.send_header("Content-Type", r.content_type)
        self.send_header("Content-Length", str(len(r.body)))
        self.send_header("Cache-Control", "private, max-age=0")
        for k, v in r.headers.items():
            self.send_header(k, v)
        for attr, header in META:
            value = getattr(r, attr)
            if value is not None:
                self.send_header(header, value)
        self.end_headers()
        if not head_only:
            self.wfile.write(r.body)

    def do_GET(self):
        self._serve()

    def do_HEAD(self):
        self._serve(head_only=True)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(min(n, 1 << 20))
        self._serve()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


def main() -> int:
    port = int(sys.argv[1])
    variant = os.environ.get("FAKEWIKI_VARIANT", "")
    world = World(Path(os.environ.get("FAKEWIKI_CORPUS", "/app/fixtures/corpus.json")), variant)
    Handler.world = world
    server = Server(("127.0.0.1", port), Handler)
    documents = [{"url": u, "topic": t, "source": s, "stance": st} for u, _, _, t, s, st in world.documents()]
    print(json.dumps({"variant": variant, "hosts": HOST_IPS, "documents": documents}), flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
