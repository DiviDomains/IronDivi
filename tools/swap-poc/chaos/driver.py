#!/usr/bin/env python3
"""Chaos driver: crash/outage recovery runs against divi-swapd (stdlib only).

Scenarios (each is one full swap):
  crash        kill -9 the maker in accepted, taker_lock_seen, taker_lock_confirmed, maker_locked,
               maker_lock_confirmed, taker_claimed, maker_claimed; restart; finish.
  refund       taker never claims; kill -9 in maker_refundable and maker_refunded; finish.
  rpc_outage   DIVI RPC proxy returns 502 for --rpc-outage-secs mid-swap, then recovers.
  esplora_429  Esplora proxy returns 429+Retry-After for --esplora-429-secs mid-swap, then recovers.

A state is held with SQLite triggers on the maker DB: once the row is in state S, every write that
would move it elsewhere aborts. The driver waits for S, kill -9s the daemon, lifts the hold and
restarts it. The engine is untouched. Maker keys stay in 1Password (op:// refs in the generated
config); nothing secret is written, printed or put on a command line.

Progress is kept in <workdir>/progress.json so a re-run resumes. Result lines
(`- chaos_<key>: <swap_id> <final_txid>`) go to stdout and <workdir>/results.txt.
"""
import argparse
import json
import os
import shutil
import socket
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDER = ["accepted", "taker_lock_seen", "taker_lock_confirmed", "maker_locked",
         "maker_lock_confirmed", "taker_claimed", "maker_claimed", "done"]
REFUND_ORDER = ["maker_lock_confirmed", "maker_refundable", "maker_refunded", "done"]
KEYS = {
    "maker_divi": "op://global_secret_store/IronDivi Swap POC - maker-divi/password",
    "maker_btc": "op://global_secret_store/IronDivi Swap POC - maker-btc/password",
    "taker_divi": "op://global_secret_store/IronDivi Swap POC - taker-divi/password",
    "taker_btc": "op://global_secret_store/IronDivi Swap POC - taker-btc/password",
}
DIVI_UPSTREAM = "https://services.divi.domains/api/testnet/rpc/"
BTC_NETWORK = os.environ.get("SWAP_BTC_NETWORK", "signet")  # or "testnet" (testnet3)
ESPLORA_UPSTREAM = f"https://mempool.space/{BTC_NETWORK}/api"
# Public address of the shared taker BTC key; the driver waits for its coins to confirm before a
# lock so it never builds a second unconfirmed chain on a UTXO another lane is spending.
TAKER_BTC_ADDRESS = "tb1qa826ffe73xnqsm64x6fvln7sl0zp3rgfdq3hpg"
DIVI_SCAN_FROM = 339800
# A finished e2e-local maker wallet (scanned from DIVI_SCAN_FROM) seeds ours, so the first start
# resumes from its cursor instead of a ~15 min scan. Never one a live daemon has open.
WALLET_SEEDS = [Path.home() / ".local/state/iron-divi-swap-poc" / d / "maker-wallet.json"
                for d in ("case-d-live", "happy-live")]


def log(msg):
    print(f"[chaos {time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def http(method, url, body=None, timeout=15):
    req = urllib.request.Request(url, data=body, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


class Run:
    def __init__(self, a, scenario):
        self.a = a
        self.scenario = scenario
        self.dir = Path(a.workdir) / scenario
        self.dir.mkdir(parents=True, exist_ok=True)
        self.db = self.dir / "maker.db"
        self.taker_db = self.dir / "taker.db"
        self.progress_path = self.dir / "progress.json"
        self.progress = json.loads(self.progress_path.read_text()) if self.progress_path.exists() else {}
        self.maker = f"http://127.0.0.1:{a.port}"
        self.daemon = None
        self.proxies = []
        self.divi_px = f"http://127.0.0.1:{a.port + 1}"
        self.esp_px = f"http://127.0.0.1:{a.port + 2}"
        self.stop = threading.Event()

    # -- persistence ---------------------------------------------------------------------
    def save(self, **kv):
        self.progress.update(kv)
        self.progress_path.write_text(json.dumps(self.progress, indent=1))

    # -- processes -----------------------------------------------------------------------
    def wallet(self):
        """One maker DIVI wallet for every scenario (they run one at a time), seeded once."""
        w = Path(self.a.workdir) / "maker-divi-wallet.json"
        if not w.exists():
            seed = next((s for s in WALLET_SEEDS if s.exists()), None)
            if seed:
                json.loads(seed.read_text())  # refuse a torn copy
                shutil.copyfile(seed, w)
                log(f"maker wallet seeded from {seed}")
        return w

    def write_config(self):
        a = self.a
        lines = [
            f'listen = "127.0.0.1:{a.port}"', f'db_path = "{self.db}"', 'profile = "testnet"',
            "tick_secs = 3",
        ]
        if a.backend == "live":
            if self.scenario == "refund":
                # Short timeouts so the refund path finishes in about an hour. The taker claims
                # only with > 1800 s left, so the other scenarios keep the testnet profile.
                lines += ["[swap]", f"maker_timeout_secs = {a.maker_timeout}",
                          f"taker_timeout_secs = {a.taker_timeout}"]
            lines += [
                "[divi]", f'rpc_url = "{self.divi_px}/"', f'key = "{KEYS["maker_divi"]}"',
                f'wallet_path = "{self.wallet()}"', f"scan_from_height = {DIVI_SCAN_FROM}",
                "[btc]", f'network = "{BTC_NETWORK}"', f'esplora_url = "{self.esp_px}"',
                f'key = "{KEYS["maker_btc"]}"',
            ]
        (self.dir / "maker.toml").write_text("\n".join(lines) + "\n")

    def check_ports(self):
        for port in (self.a.port, self.a.port + 1, self.a.port + 2):
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    raise RuntimeError(f"port {port} already in use; pass another --port")

    def start_proxies(self):
        for port, up in ((self.a.port + 1, DIVI_UPSTREAM), (self.a.port + 2, ESPLORA_UPSTREAM)):
            p = subprocess.Popen([sys.executable, str(HERE / "proxy.py"), "--upstream", up,
                                  "--port", str(port)], stdout=subprocess.DEVNULL)
            self.proxies.append(p)
        self.wait_for(lambda: self.px_ok(self.divi_px) and self.px_ok(self.esp_px), 15, "proxies up")

    def px_ok(self, base):
        try:
            http("GET", base + "/__chaos/stats", timeout=2)
            return True
        except Exception:
            return False

    def px_mode(self, base, mode, retry_after=None):
        q = f"?retry_after={retry_after}" if retry_after else ""
        http("POST", f"{base}/__chaos/mode/{mode}{q}", b"")
        log(f"proxy {base} -> {mode}{q}")

    def start_daemon(self):
        self.write_config()
        out = open(self.dir / "maker.log", "ab")
        self.daemon = subprocess.Popen(
            [str(Path(self.a.bin_dir) / "divi-swapd"), "--config", str(self.dir / "maker.toml"),
             "--backend", self.a.backend], stdout=out, stderr=out)
        self.wait_for(self.healthy, 1800, "daemon /healthz with the DIVI wallet scanned")
        log(f"daemon up pid {self.daemon.pid}")

    def healthy(self):
        try:
            h = json.loads(http("GET", self.maker + "/healthz", timeout=10))
        except Exception:
            return False
        return h.get("divi_scan", {}).get("state", "done") == "done"

    def kill9(self):
        pid = self.daemon.pid
        os.kill(pid, signal.SIGKILL)
        self.daemon.wait()
        log(f"kill -9 daemon pid {pid}")

    def cleanup(self):
        self.stop.set()
        if self.daemon and self.daemon.poll() is None:
            self.daemon.terminate()
        for p in self.proxies:
            p.terminate()

    # -- DB / holds ----------------------------------------------------------------------
    def sql(self, stmt, *args, write=False):
        con = sqlite3.connect(self.db, timeout=30)
        try:
            cur = con.execute(stmt, args)
            rows = cur.fetchall()
            con.commit()
            return rows
        finally:
            con.close()

    def row(self):
        """(id, state) of the only swap in the maker DB, or None."""
        try:
            rows = self.sql("SELECT id, state FROM maker_swaps ORDER BY created_at DESC LIMIT 1")
        except sqlite3.OperationalError:
            return None
        return rows[0] if rows else None

    def hold(self, state):
        self.release()
        for ev in ("INSERT", "UPDATE"):
            self.sql(
                f"CREATE TRIGGER IF NOT EXISTS chaos_hold_{ev.lower()} BEFORE {ev} ON maker_swaps "
                f"WHEN NEW.state <> '{state}' AND "
                f"(SELECT state FROM maker_swaps WHERE id = NEW.id) = '{state}' "
                f"BEGIN SELECT RAISE(ABORT, 'chaos hold'); END")
        log(f"hold on {state}")

    def release(self):
        try:
            for ev in ("insert", "update"):
                self.sql(f"DROP TRIGGER IF EXISTS chaos_hold_{ev}")
        except sqlite3.OperationalError:
            pass  # table not created yet

    def wait_for(self, cond, timeout, what):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return
            time.sleep(1)
        raise TimeoutError(f"timed out after {timeout}s waiting for {what}")

    def wait_state(self, state, timeout):
        self.wait_for(lambda: (self.row() or (None, None))[1] == state, timeout, f"state {state}")

    def view(self, sid):
        return json.loads(http("GET", f"{self.maker}/swaps/{sid}"))

    def final_txid(self, sid):
        v = self.view(sid)
        d = (v.get("maker_leg") or {}).get("spend_txid") if v["state"].lower() == "makerrefunded" else None
        return d or (v["taker_leg"].get("spend_txid")) or (v.get("maker_leg") or {}).get("spend_txid")

    # -- taker ---------------------------------------------------------------------------
    def taker(self, *args):
        cmd = [str(Path(self.a.bin_dir) / "divi-swap"), "--db", str(self.taker_db),
               "--backend", self.a.backend, "--divi-key", KEYS["taker_divi"],
               "--btc-key", KEYS["taker_btc"], *args]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if r.returncode != 0:
            raise RuntimeError(f"divi-swap {args[0]} failed: {r.stderr.strip()[-400:]}")
        return r.stdout.strip()

    def accept(self):
        return self.taker("accept", "--maker", self.maker, "--offer", "divi-btc-testnet",
                          "--btc-sats", str(self.a.btc_sats)).splitlines()[-1].strip()

    def claim_loop(self, local):
        def go():
            while not self.stop.is_set():
                try:
                    self.taker("claim", "--swap", local)
                except Exception as e:  # not claimable yet / transient: keep trying
                    log(f"taker claim: {str(e)[:120]}")
                self.stop.wait(20)
        threading.Thread(target=go, daemon=True).start()

    # -- kill sequence -------------------------------------------------------------------
    def kill_in(self, state, timeout, then=None):
        """Hold `state`, wait for the row to reach it, kill -9, restart.

        `then` is the next state to kill in: its hold goes in before the restart, because some
        states are left within the same step they are entered in (maker_refunded -> done,
        taker_claimed -> maker_claimed)."""
        if state in self.progress.get("killed", []):
            return
        self.hold(state)
        self.wait_state(state, timeout)
        time.sleep(2)  # let the daemon run into the hold at least once
        self.kill9()
        if then:
            self.hold(then)
        else:
            self.release()
        self.save(killed=self.progress.get("killed", []) + [state])
        self.start_daemon()

    def taker_funds_settled(self):
        try:
            utxos = json.loads(http("GET", f"{ESPLORA_UPSTREAM}/address/{TAKER_BTC_ADDRESS}/utxo"))
        except Exception as e:
            log(f"taker utxo check: {e}")
            return False
        confirmed = sum(u["value"] for u in utxos if u["status"]["confirmed"])
        pending = [u for u in utxos if not u["status"]["confirmed"]]
        return not pending and confirmed >= self.a.btc_sats + 5000

    def lock(self, local):
        """Fund the taker's BTC HTLC once the shared taker coins are confirmed. The signed tx is
        persisted before broadcast, so a retry rebroadcasts the same bytes."""
        if self.progress.get("locked"):
            return
        for attempt in range(60):
            if self.a.backend == "live":
                self.wait_for(self.taker_funds_settled, self.a.state_timeout,
                              "confirmed taker BTC coins")
            try:
                self.taker("lock", "--swap", local)
                break
            except RuntimeError as e:
                log(f"taker lock attempt {attempt + 1}: {str(e)[:200]}")
                time.sleep(60)
        else:
            raise RuntimeError("taker lock kept failing")
        self.save(locked=True)

    def taker_refund(self, local, timeout):
        """Refund the taker's BTC once its timelock passes; returns the refund txid."""
        end = time.time() + timeout
        while time.time() < end:
            try:
                self.taker("refund", "--swap", local)
            except Exception as e:
                log(f"taker refund: {str(e)[:120]}")
            try:
                ids = dict(l.split("=", 1) for l in self.taker("txids", "--swap", local).splitlines()
                           if "=" in l)
            except Exception as e:
                log(f"taker txids: {str(e)[:120]}")
                ids = {}
            if ids.get("btc_refund_by_taker"):
                return ids["btc_refund_by_taker"]
            time.sleep(600)
        raise TimeoutError("taker BTC refund did not happen")

    def wait_done(self, sid, timeout):
        self.wait_for(lambda: self.view(sid)["state"].lower() == "done", timeout, "state done")

    def result(self, keys, sid, txid):
        for k in keys:
            line = f"- chaos_{k}: {sid} {txid}"
            print(line, flush=True)
            with open(Path(self.a.workdir) / "results.txt", "a") as f:
                f.write(line + "\n")

    def run_mock_mechanics(self):
        """Mock chains are per-process (taker and maker share none) and die with the daemon, so a
        swap cannot finish. Prove only what the driver owns: hold, kill -9, restart, persistence,
        proxy mode switching."""
        self.hold("accepted")
        sid, _ = self.begin()
        self.kill_in("accepted", 60)
        row = self.row()
        assert row and row[0] == sid and row[1] == "accepted", f"row lost over kill -9: {row}"
        for base, mode in ((self.divi_px, "502"), (self.esp_px, "429")):
            self.px_mode(base, mode, 5 if mode == "429" else None)
            try:
                http("GET", base + "/x", timeout=5)
                raise AssertionError(f"{mode} not injected")
            except urllib.error.HTTPError as e:
                assert e.code == int(mode), e.code
            self.px_mode(base, "pass")
        log(f"mock mechanics ok ({self.scenario})")

    # -- scenarios -----------------------------------------------------------------------
    def go(self):
        self.check_ports()
        try:
            self.start_proxies()
            self.start_daemon()
            if self.a.backend == "mock":
                self.run_mock_mechanics()
            else:
                getattr(self, "run_" + self.scenario)()
        finally:
            self.cleanup()

    def begin(self):
        """accept (or resume) and return (maker_id, taker_local_id)."""
        if "local" not in self.progress:
            self.save(local=self.accept())
        r = self.row()
        return r[0], self.progress["local"]

    def run_crash(self):
        t = self.a.state_timeout
        self.hold("accepted")
        sid, local = self.begin()
        self.save(sid=sid)
        self.kill_in("accepted", t, then=ORDER[1])
        self.lock(local)
        for i, st in enumerate(ORDER[1:-1], 1):
            if st == "taker_claimed":
                self.claim_loop(local)
            self.kill_in(st, t, then=ORDER[i + 1] if ORDER[i + 1] != "done" else None)
        self.wait_done(sid, t)
        self.result(ORDER[:-1], sid, self.final_txid(sid))

    def run_refund(self):
        t = self.a.state_timeout
        sid, local = self.begin()
        self.save(sid=sid)
        self.lock(local)
        wait = max(t, self.a.maker_timeout + 3600)
        self.kill_in("maker_refundable", wait, then="maker_refunded")
        self.kill_in("maker_refunded", wait)
        self.wait_done(sid, t)
        self.result(["maker_refundable", "maker_refunded"], sid, self.final_txid(sid))
        # The taker never claimed: take its BTC back after the taker timelock (BTC MTP lags).
        if self.a.backend == "live" and "taker_refund" not in self.progress:
            self.save(taker_refund=self.taker_refund(local, self.a.taker_timeout + 4 * 3600))
        log(f"taker BTC refund {self.progress.get('taker_refund')}")

    def _outage(self, base, mode, secs, retry_after, key):
        t = self.a.state_timeout
        sid, local = self.begin()
        self.save(sid=sid)
        self.lock(local)
        self.wait_state("maker_locked", t)  # mid-swap: DIVI HTLC broadcast, confirmations pending
        self.px_mode(base, mode, retry_after)
        log(f"outage {mode} for {secs}s")
        time.sleep(secs)
        self.px_mode(base, "pass")
        self.claim_loop(local)
        self.wait_done(sid, t)
        self.result([key], sid, self.final_txid(sid))

    def run_rpc_outage(self):
        self._outage(self.divi_px, "502", self.a.rpc_outage_secs, None, "rpc_outage")

    def run_esplora_429(self):
        self._outage(self.esp_px, "429", self.a.esplora_429_secs, 30, "esplora_429")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--backend", choices=("mock", "live"), default="mock")
    ap.add_argument("--scenario", choices=("crash", "refund", "rpc_outage", "esplora_429", "all"),
                    default="all")
    ap.add_argument("--workdir", help="default ~/.cache/swap-chaos/<backend>")
    ap.add_argument("--bin-dir", default=str(HERE.parent.parent.parent / "target" / "debug"))
    ap.add_argument("--port", type=int, default=18600, help="maker port; proxies use port+1, +2")
    ap.add_argument("--btc-sats", type=int, default=20000)
    ap.add_argument("--maker-timeout", type=int, default=3600, help="refund scenario only")
    ap.add_argument("--taker-timeout", type=int, default=14410, help="refund scenario only")
    ap.add_argument("--rpc-outage-secs", type=int, default=330)
    ap.add_argument("--esplora-429-secs", type=int, default=150)
    ap.add_argument("--state-timeout", type=int, default=5400, help="max wait per state, secs")
    a = ap.parse_args()
    a.workdir = a.workdir or os.path.expanduser(f"~/.cache/swap-chaos/{a.backend}")
    Path(a.workdir).mkdir(parents=True, exist_ok=True)
    if a.btc_sats > 20000:
        sys.exit("refusing: swap amount above the 20,000 sat lane cap")
    # refund last: its taker BTC stays locked until the taker timelock, then is refunded.
    names = ["crash", "rpc_outage", "esplora_429", "refund"] if a.scenario == "all" else [a.scenario]
    for i, name in enumerate(names):
        a_i = argparse.Namespace(**vars(a))
        a_i.port = a.port + 10 * i
        Run(a_i, name).go()


if __name__ == "__main__":
    main()
