#!/usr/bin/env python3
"""Fault-injecting HTTP forward proxy for the swap chaos lane (stdlib only).

Point a daemon's `rpc_url` / `esplora_url` at http://127.0.0.1:<port> and give the proxy the
real upstream base with --upstream; every request path is appended to it. The mode is switched
at runtime over the same port:

    POST /__chaos/mode/<pass|502|reset|429|hang>[?retry_after=<secs>]
    GET  /__chaos/stats

Modes: pass (forward), 502 (Bad Gateway), reset (close the socket without a reply, which the
client sees as a connection error), 429 (Too Many Requests + Retry-After), hang (accept the
request and never answer; the client's own timeout fires).
"""
import argparse
import json
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODES = ("pass", "502", "reset", "429", "hang")
HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
              "proxy-authorization", "proxy-authenticate", "host", "content-length"}


class State:
    def __init__(self, upstream):
        self.upstream = upstream.rstrip("/")
        self.mode = "pass"
        self.retry_after = 30
        self.lock = threading.Lock()
        self.counts = {}  # outcome -> n
        self.mode_since = time.time()

    def set_mode(self, mode, retry_after=None):
        with self.lock:
            self.mode = mode
            self.mode_since = time.time()
            if retry_after is not None:
                self.retry_after = retry_after

    def bump(self, outcome):
        with self.lock:
            self.counts[outcome] = self.counts.get(outcome, 0) + 1

    def snapshot(self):
        with self.lock:
            return {"mode": self.mode, "retry_after": self.retry_after,
                    "mode_since": self.mode_since, "counts": dict(self.counts)}


def make_handler(state):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # quiet; stats endpoint is the record
            pass

        def _reply(self, status, body=b"", headers=()):
            self.send_response(status)
            for k, v in headers:
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _admin(self, parsed):
            parts = parsed.path.split("/")  # ['', '__chaos', 'mode', 'x']
            if len(parts) == 3 and parts[2] == "stats":
                return self._reply(200, json.dumps(state.snapshot()).encode(),
                                   [("Content-Type", "application/json")])
            if len(parts) == 4 and parts[2] == "mode" and parts[3] in MODES:
                q = urllib.parse.parse_qs(parsed.query)
                ra = int(q["retry_after"][0]) if "retry_after" in q else None
                state.set_mode(parts[3], ra)
                return self._reply(200, json.dumps(state.snapshot()).encode(),
                                   [("Content-Type", "application/json")])
            return self._reply(404, b"unknown chaos command")

        def _handle(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else None
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path.startswith("/__chaos/"):
                return self._admin(parsed)
            mode = state.snapshot()["mode"]
            if mode == "reset":
                state.bump("reset")
                self.close_connection = True
                self.connection.close()
                return None
            if mode == "502":
                state.bump("502")
                return self._reply(502, b"chaos: bad gateway")
            if mode == "429":
                state.bump("429")
                return self._reply(429, b"chaos: slow down",
                                   [("Retry-After", str(state.snapshot()["retry_after"]))])
            if mode == "hang":
                state.bump("hang")
                time.sleep(600)
                self.close_connection = True
                return None
            return self._forward(body)

        def _forward(self, body):
            req = urllib.request.Request(state.upstream + self.path, data=body,
                                         method=self.command)
            for k, v in self.headers.items():
                if k.lower() not in HOP_BY_HOP:
                    req.add_header(k, v)
            try:
                with urllib.request.urlopen(req, timeout=60) as r:
                    status, data, hdrs = r.status, r.read(), r.getheaders()
            except urllib.error.HTTPError as e:  # upstream's own 4xx/5xx pass straight through
                status, data, hdrs = e.code, e.read(), list(e.headers.items())
            except Exception as e:  # noqa: BLE001 - upstream down: surface as 502
                state.bump("upstream_error")
                return self._reply(502, f"chaos: upstream error {e}".encode())
            state.bump("forwarded")
            keep = [(k, v) for k, v in hdrs
                    if k.lower() not in HOP_BY_HOP and k.lower() != "content-encoding"]
            return self._reply(status, data, keep)

        do_GET = do_POST = do_PUT = do_HEAD = _handle

    return Handler


def serve(upstream, port):
    state = State(upstream)
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(state))
    srv.daemon_threads = True
    return srv, state


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--port", type=int, required=True)
    a = ap.parse_args()
    srv, _ = serve(a.upstream, a.port)
    print(f"chaos proxy 127.0.0.1:{a.port} -> {a.upstream}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
