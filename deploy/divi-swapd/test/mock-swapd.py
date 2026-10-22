#!/usr/bin/env python3
"""Mock divi-swapd for the nginx test. stdlib only. Usage: mock-swapd.py PORT [ready|scanning] [several|empty|hostile]
Every response echoes the request path in X-Mock-Path so a test can prove what reached it."""
import json, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

port = int(sys.argv[1]); health_mode = sys.argv[2] if len(sys.argv) > 2 else "ready"
offers_mode = sys.argv[3] if len(sys.argv) > 3 else "several"
OFF = {"id": "divi-btc-testnet", "direction": "taker_pays_btc", "counter_chain": "btc",
       "divi_sats_per_btc": 300000000000000, "min_btc_sats": 5000, "max_btc_sats": 50000}
HOSTILE = dict(OFF, id="<script>alert(1)</script>", counter_chain="<img src=x onerror=alert(1)>")
HEALTH = {"ok": True, "version": "0.2.6", "divi": {"tip": 1, "error": None}, "btc": {"tip": 2, "error": None},
          "counters": {"ltc": {"tip": 3, "error": None}}, "divi_scan": {"state": "done", "next_height": 9, "target_height": 9}}
if health_mode == "scanning":
    HEALTH.update(ok=False, divi_scan={"state": "scanning", "next_height": 355190, "target_height": 361301})
OFFERS = {"several": [OFF, dict(OFF, id="ltc-divi-testnet", direction="taker_pays_divi", counter_chain="ltc")],
          "empty": [], "hostile": [HOSTILE]}[offers_mode]

class H(BaseHTTPRequestHandler):
    def _send(self, body, code=200):
        b = json.dumps(body).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("X-Mock-Path", self.path); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/healthz": self._send(HEALTH)
        elif self.path == "/offers": self._send(OFFERS)
        elif self.path.startswith("/swaps/") or self.path.startswith("/xmr/swaps"): self._send({"mock": "api", "path": self.path})
        else: self._send({"error": "not found"}, 404)
    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", 0))); self._send({"mock": "post", "path": self.path})
    def log_message(self, *a): pass

HTTPServer(("127.0.0.1", port), H).serve_forever()
