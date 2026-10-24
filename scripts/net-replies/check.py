#!/usr/bin/env python3
"""Network, masternode and spork RPC replies of Divi Core divid and irondivid,
side by side on regtest: two divid connected to each other and two irondivid
connected to each other, the same calls on both kinds, and every reply compared
field by field (names, JSON types, values, error codes and texts), before and
after a restart of all four. Each row prints PASS (same as divid), KNOWN (a
difference listed in README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import json
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row
# is changed before it is compared
INJECT = os.environ.get("NET_REPLIES_INJECT", "")
# For looking into a difference: both replies of every row that differs are
# written to this directory
DUMP = os.environ.get("NET_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120
# A node that cannot bind its ports is started again on new ones, this often
BIND_RETRIES = 5
BANTIME = 86400

# Differences listed in README.md with divid's source line, one per row name:
# (reason, shape). shape takes the two raw outcomes and is true only for the
# difference described, so a KNOWN row that matches divid, or differs in another
# way, is a FAIL.

# The paths that differ in the result row being compared (set by compare)
LAST_DIFF = set()


def only(*paths):
    """Both are results, and the fields that differ are some of `paths`"""
    return lambda c, i: c[0] == i[0] == "ok" and LAST_DIFF and LAST_DIFF <= set(paths)


def pair(core, iron):
    """Exactly these two outcomes"""
    return lambda c, i: c == core and i == iron


NOT_FOUND = ("err", -32601, "Method not found")
EMPTY_BANS = ("ok", {"banned:": "[\n]"})

PEERINFO = ("services: irondivid does not serve bloom filters and does not advertise NODE_BLOOM, which divid "
            "sets (NetworkLocalAddressHelpers.cpp:224-227) [open]; subver: irondivid's own user agent [by design]; "
            "synced_headers/synced_blocks: irondivid gives -1, divid the peer's synced heights "
            "(rpcnet.cpp:139-140) [open]",
            only("[0].services", "[0].subver", "[0].synced_headers", "[0].synced_blocks"))
NETINFO_FIELDS = (".connections_in", ".connections_out", ".localservices", ".networks[2].limited", ".subversion",
                  ".version")
NETINFO = ("connections_in/out: irondivid's extra fields [by design]; localservices: no NODE_BLOOM, as getpeerinfo "
           "[open]; onion limited: irondivid cannot address .onion peers [by design]; subversion: its user agent "
           "[by design]; version: irondivid's own (docs/divid-differences.md R5) [by design]",
           only(*NETINFO_FIELDS))
MNCOUNT = ("irondivid adds the tier counts copper..diamond [by design]",
           only(".copper", ".silver", ".gold", ".platinum", ".diamond"))
MNSYNC = ("currentMasternodeSyncStatus: divid gives its sync phase (0, then 1 after a restart, with no masternodes "
          "on regtest: rpcmisc.cpp:212, masternode-sync.h:42-47); irondivid has no masternode sync and gives 999, finished [open]",
          only(".currentMasternodeSyncStatus"))
BANLIST = ("divid gives {\"banned:\": \"<text list>\"}, irondivid an array (docs/rpc-parity-audit.md: "
           "listbanned; divid: rpcmisc.cpp:1023-1030, PeerBanningService.cpp:23-34) [by design]",
           pair(EMPTY_BANS, ("ok", [])))
EXTRA = "{} is not a divid method (rpcserver.cpp:325-409); irondivid has it (docs/rpc-parity-audit.md) [by design]"


def iron_only(method, reply):
    return (EXTRA.format(method) + f"; irondivid's reply is {reply!r}", pair(NOT_FOUND, reply))


KNOWN = {
    "getpeerinfo (node 1, inbound peer)": PEERINFO,
    "getpeerinfo (node 2, outbound peer)": PEERINFO,
    "after restart: getpeerinfo (node 1, inbound peer)": PEERINFO,
    "after restart: getpeerinfo (node 2, outbound peer)": PEERINFO,
    "getnetworkinfo": NETINFO,
    "after restart: getnetworkinfo": NETINFO,
    "getmasternodecount": MNCOUNT,
    "after restart: getmasternodecount": MNCOUNT,
    "mnsync status": MNSYNC,
    "after restart: mnsync status": MNSYNC,
    "listbanned (none)": BANLIST,
    "after restart: listbanned (none)": BANLIST,
    "after restart: listbanned": BANLIST,
    "listbanned (after clearbanned)": BANLIST,
    "getaddednodeinfo false <ip without a port>": (
        "divid keeps the node as written (rpcnet.cpp:220-227); irondivid keeps the address, with the network's "
        "port [open]",
        pair(("ok", [{"addednode": "192.0.2.3"}]), ("ok", [{"addednode": "192.0.2.3:51476"}]))),
    "getaddednodeinfo true <ip without a port>": (
        "the node as written, as above; its address, with the network's port, is the same [open]",
        only("[0].addednode")),
    "setban 192.0.2.10 add": iron_only("setban", ("ok", None)),
    "setban 192.0.2.10 add again": iron_only("setban", ("ok", None)),
    "setban of a bad subnet": iron_only("setban", ("err", -30, "Invalid IP: not-a-subnet")),
    "setban 192.0.2.11 add <absolute time>": iron_only("setban", ("ok", None)),
    "setban remove of an address not banned": iron_only("setban", ("err", -30, "IP not in ban list")),
    "disconnectnode of an address not connected": iron_only("disconnectnode", ("err", -29, "Node not connected")),
    "ban outdated (none outdated)": (
        "irondivid does not ban outdated peers (docs/rpc-parity-audit.md: ban outdated; divid: net.cpp:357-393) "
        "[by design]",
        pair(("ok", {"Banned": []}),
             ("err", -1, "ban outdated is not supported: peer versions are not tracked"))),
    "ban 127.0.0.1 (node 2's address)": (
        "divid compares the address given with each peer's ip:port text, so it never finds a connected peer "
        "(net.cpp:395-407); irondivid bans node 2 [by design]",
        pair(("ok", {"Banned": "Could not find matching node to ban"}), ("ok", {"Banned": "127.0.0.1"}))),
    "getconnectioncount (after ban 127.0.0.1)": ("node 2 is banned on irondivid only, as above [by design]",
                                                 pair(("ok", 1), ("ok", 0))),
    "listbanned (after ban 127.0.0.1)": (
        "node 2 is banned on irondivid only, and the list's form differs, as above [by design]",
        lambda c, i: c == EMPTY_BANS and i[0] == "ok" and isinstance(i[1], list) and len(i[1]) == 1
        and i[1][0].get("address") == "127.0.0.1"),
}

fails = 0


def row(name, core, iron, same, raw=None):
    global fails
    if name in KNOWN:
        reason, shape = KNOWN[name]
        if same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif raw is not None and shape(*raw):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
    if DUMP and not same and raw is not None:
        os.makedirs(DUMP, exist_ok=True)
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"row": name, "divid": raw[0], "irondivid": raw[1]}, f, indent=1, sort_keys=True)
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}", flush=True)


def free_port():
    """A port nothing listens on now (the system picks it)"""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Node:
    def __init__(self, name, binary, index, extra):
        """extra: divi.conf lines; a callable is evaluated at each start, so a
        line naming another node's port follows that node to new ports"""
        self.name = name
        self.binary = binary
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"net{index}"
        self.password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        self.extra = list(extra)
        os.makedirs(self.dir)
        self.proc = None
        self.starts = 0
        self.why = ""

    def write_conf(self):
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={self.password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0", f"bantime={BANTIME}",
        ] + [line() if callable(line) else line for line in self.extra]
        path = os.path.join(self.dir, "divi.conf")
        fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        os.replace(path + ".new", path)

    def launch(self):
        self.starts += 1
        self.write_conf()
        self.err = os.path.join(WORK, f"{self.name}.{self.starts}.err")
        with open(os.path.join(WORK, f"{self.name}.{self.starts}.out"), "w") as o, open(self.err, "w") as e:
            self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                         stdout=o, stderr=e, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def log_tail(self, n=15):
        """The last lines of the node's debug.log (divid keeps it in regtest/),
        or of its stderr when there is none"""
        for path in (os.path.join(self.dir, "regtest", "debug.log"), os.path.join(self.dir, "debug.log"), self.err):
            try:
                with open(path, errors="replace") as f:
                    lines = f.read().splitlines()
                if lines:
                    return lines[-n:]
            except OSError:
                pass
        return []

    def start(self):
        """True once RPC answers. A node that exits at once because a port is
        taken is started again on new ports; otherwise `why` says how it ended:
        its exit code and the last 15 lines of its debug.log"""
        retries = BIND_RETRIES
        self.launch()
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            code = self.proc.poll()
            if code is not None:
                tail = self.log_tail()
                text = "\n".join(tail)
                if retries and ("Address already in use" in text or "Unable to bind" in text):
                    retries -= 1
                    old = (self.p2p, self.rpcport)
                    self.p2p, self.rpcport = free_port(), free_port()
                    print(f"# {self.name}: ports {old[0]}/{old[1]} in use, starting again on "
                          f"{self.p2p}/{self.rpcport}", flush=True)
                    self.launch()
                    continue
                self.proc = None
                self.why = f"exited with code {code}; last lines of its log:\n" + "\n".join(
                    "#     " + line for line in tail)
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.25)
        self.why = f"no RPC answer within {START_TIMEOUT} s; last lines of its log:\n" + "\n".join(
            "#     " + line for line in self.log_tail())
        return False

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:120]}")
        return out[1]

    def stop(self):
        if self.proc is None:
            return
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.proc = None


# --- how replies are compared ----------------------------------------------------

def iron_row(name, expected, got):
    """A row with no divid counterpart: irondivid against the expected outcome"""
    global fails
    same = expected == got
    if name in KNOWN:
        reason, shape = KNOWN[name]
        word, note = (("FAIL", "  [listed as KNOWN but now as expected: update README.md]") if same else
                      ("KNOWN", "  [known: " + reason + "]") if shape(expected, got) else
                      ("FAIL", "  [listed as KNOWN, but differs in another way]"))
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  expected={expected}  irondivid={got}  [irondivid only]{note}", flush=True)


def kind(v):
    """The JSON type of a value: an integer and a number with a fraction differ"""
    if v is None:
        return "null"
    return {bool: "bool", int: "int", float: "number", str: "string", list: "array", dict: "object"}[type(v)]


def flatten(v, vary, path=""):
    """{path: value} of every leaf; a field named in `vary` (it changes from one
    moment to the next) keeps only its type"""
    out = {}
    if isinstance(v, dict):
        out[path or "."] = "object"
        for k, x in v.items():
            out.update(flatten(x, vary, f"{path}.{k}"))
    elif isinstance(v, list):
        out[path or "."] = f"array[{len(v)}]"
        for i, x in enumerate(v):
            out.update(flatten(x, vary, f"{path}[{i}]"))
    else:
        leaf = path.rsplit(".", 1)[-1]
        out[path or "."] = f"<{kind(v)}>" if leaf in vary else (kind(v), v)
    return out


def differences(a, b):
    """Every path whose name, type or value differs"""
    return [(k, a.get(k, "absent"), b.get(k, "absent")) for k in sorted(set(a) | set(b))
            if a.get(k, "absent") != b.get(k, "absent")]


def leaf(x):
    return x if isinstance(x, str) else f"{x[1]!r}({x[0]})"


def show(out):
    if out[0] == "err":
        return f"error {out[1]} \"{str(out[2]).splitlines()[0][:90] if out[2] else ''}\""
    return json.dumps(out[1], sort_keys=True)[:140]


def compare(name, c, i, vary=(), message=True):
    """Same outcome; for an error the same code and message (the first line
    only when message is "first-line"); for a result every field's name, type
    and value, except the values of the fields in `vary`"""
    if name == INJECT and i[0] == "ok":
        i = ("ok", {"injected": True, "reply": i[1]})
    elif name == INJECT:
        i = ("err", (i[1] or 0) + 1, i[2])
    LAST_DIFF.clear()
    if c[0] == "err" and i[0] == "err":
        cm, im = str(c[2]), str(i[2])
        if message == "first-line":
            cm, im = cm.splitlines()[0] if cm else "", im.splitlines()[0] if im else ""
        same = c[1] == i[1] and (not message or cm == im)
        row(name, show(c), show(i), same, (c, i))
    elif c[0] == "ok" and i[0] == "ok":
        d = differences(flatten(c[1], set(vary)), flatten(i[1], set(vary)))
        LAST_DIFF.update(k for k, _, _ in d)
        if not d:
            row(name, show(c), "same", True, (c, i))
        else:
            row(name, "; ".join(f"{k}={leaf(x)}" for k, x, _ in d[:6]),
                "; ".join(f"{k}={leaf(y)}" for k, _, y in d[:6]) + (f" (+{len(d) - 6} more)" if len(d) > 6 else ""),
                False, (c, i))
    else:
        row(name, show(c), show(i), False, (c, i))


def both(name, method, *params, vary=(), message=True, on=1):
    c = (C1 if on == 1 else C2).call(method, *params)
    i = (I1 if on == 1 else I2).call(method, *params)
    compare(name, c, i, vary, message)
    return c, i


def wait_for(fn, secs):
    deadline = time.time() + secs
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(0.25)
    return False


def need(ok, what):
    if not ok:
        print(f"FAIL   setup: {what}", flush=True)
        sys.exit(1)


def setup_failed(kind_, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

# --- the four nodes -----------------------------------------------------------------

C1 = Node("divid1", DIVID, 0, ["listen=1"])
C2 = Node("divid2", DIVID, 1, ["listen=0", lambda: f"connect=127.0.0.1:{C1.p2p}"])
I1 = Node("irondivid1", IRONDIVID, 2, ["listen=1"])
I2 = Node("irondivid2", IRONDIVID, 3, ["listen=0", lambda: f"connect=127.0.0.1:{I1.p2p}"])
PAIRS = ((C1, C2), (I1, I2))


def start_all():
    for n in (C1, C2, I1, I2):
        need(n.start(), f"{n.name} did not start: {n.why}")


def connected(n=1):
    return all(a.rpc("getconnectioncount") == n and b.rpc("getconnectioncount") == n for a, b in PAIRS)


def stop_all():
    for n in (C2, I2, C1, I1):
        n.stop()


start_all()
print(f"# divid {C1.rpc('getinfo').get('version')}, irondivid {I1.rpc('getinfo').get('version')}", flush=True)
# A chain of a few blocks on node 1 of each pair, followed by node 2
for a, b in PAIRS:
    a.rpc("setgenerate", 5)
need(wait_for(lambda: connected() and all(b.rpc("getblockcount") == 5 for _, b in PAIRS), 90),
     "a pair did not connect or sync")

# Fields whose values change from moment to moment, or with the port a node was given
PEER_VARY = {"id", "addr", "addrlocal", "lastsend", "lastrecv", "bytessent", "bytesrecv", "conntime",
             "pingtime", "pingwait", "minping", "timeoffset", "bytessent_per_msg", "bytesrecv_per_msg"}
TOTALS_VARY = {"totalbytesrecv", "totalbytessent", "timemillis"}
UNREACHABLE = "192.0.2.1:51476"   # TEST-NET-1 (RFC 5737): no node answers there
UNREACHABLE2 = "192.0.2.2:51476"


def replies(prefix):
    """The rows; `prefix` names the pass (before or after the restart)"""
    p = prefix
    both(f"{p}getconnectioncount", "getconnectioncount")
    both(f"{p}getpeerinfo (node 1, inbound peer)", "getpeerinfo", vary=PEER_VARY)
    both(f"{p}getpeerinfo (node 2, outbound peer)", "getpeerinfo", vary=PEER_VARY, on=2)
    both(f"{p}getnetworkinfo", "getnetworkinfo", vary={"timeoffset"})
    both(f"{p}getnettotals", "getnettotals", vary=TOTALS_VARY)
    both(f"{p}ping", "ping")
    both(f"{p}getaddednodeinfo false (none added)", "getaddednodeinfo", False)
    both(f"{p}getaddednodeinfo true (none added)", "getaddednodeinfo", True)

    both(f"{p}spork show", "spork", "show")
    both(f"{p}spork active", "spork", "active")
    both(f"{p}getmasternodecount", "getmasternodecount")
    both(f"{p}listmasternodes", "listmasternodes")
    both(f"{p}getmasternodestatus (no masternode)", "getmasternodestatus")
    both(f"{p}mnsync status", "mnsync", "status")
    both(f"{p}listbanned (none)", "listbanned")


replies("")

# A version names the height at the time it is sent (Node.cpp:994-1005), and a
# node asks a new peer for blocks whatever height it names (main.cpp:1130-1142):
# node 2 stops, node 1 mines two blocks, node 2 starts again and dials node 1,
# which is at a height it reached after it started
for _, b in PAIRS:
    b.stop()
for a, _ in PAIRS:
    a.rpc("setgenerate", 2)
for _, b in PAIRS:
    need(b.start(), f"{b.name} did not start again: {b.why}")
need(wait_for(connected, 90), "node 2 did not connect again")
for on, what in ((1, "node 1 sees node 2"), (2, "node 2 sees node 1")):
    c = [p.get("startingheight") for p in (C1 if on == 1 else C2).rpc("getpeerinfo")]
    i = [p.get("startingheight") for p in (I1 if on == 1 else I2).rpc("getpeerinfo")]
    compare(f"getpeerinfo startingheight after node 2 restarts ({what})", ("ok", c), ("ok", i))
caught_up = lambda: all(b.rpc("getblockcount") == 7 for _, b in PAIRS)
wait_for(caught_up, 60)
compare("getblockcount on node 2 after it restarts (no new block)", ("ok", C2.rpc("getblockcount")),
        ("ok", I2.rpc("getblockcount")))

# addnode and getaddednodeinfo
both("addnode add", "addnode", UNREACHABLE, "add")
both("addnode add again", "addnode", UNREACHABLE, "add")
both("getaddednodeinfo false", "getaddednodeinfo", False)
both("getaddednodeinfo false <node>", "getaddednodeinfo", False, UNREACHABLE)
both("getaddednodeinfo true <node>", "getaddednodeinfo", True, UNREACHABLE)
both("getaddednodeinfo false <node not added>", "getaddednodeinfo", False, UNREACHABLE2)
both("addnode remove", "addnode", UNREACHABLE, "remove")
both("addnode remove again", "addnode", UNREACHABLE, "remove")
both("getaddednodeinfo false (after remove)", "getaddednodeinfo", False)
both("addnode onetry", "addnode", UNREACHABLE2, "onetry")
both("getaddednodeinfo false (after onetry)", "getaddednodeinfo", False)
# A node given without a port: divid keeps it as written and looks it up
# with the network's port
both("addnode <ip without a port> add", "addnode", "192.0.2.3", "add")
both("getaddednodeinfo false <ip without a port>", "getaddednodeinfo", False, "192.0.2.3")
both("getaddednodeinfo true <ip without a port>", "getaddednodeinfo", True, "192.0.2.3")
both("addnode <ip without a port> remove", "addnode", "192.0.2.3", "remove")
both("addnode <node> badcommand", "addnode", UNREACHABLE, "badcommand", message="first-line")
both("addnode with no arguments", "addnode", message="first-line")

# spork updates need the network's spork key, which nobody has on regtest
both("spork update without the spork key", "spork", "SPORK_2_SWIFTTX_ENABLED", "0")
both("spork update of an unknown spork", "spork", "SPORK_99_NONE", "0")
both("spork with no arguments", "spork", message="first-line")
both("mnsync with a bad mode", "mnsync", "bad", message="first-line")
both("listmasternodes <filter>", "listmasternodes", "nothing-matches")
both("masternode status (not a divid method)", "masternode", "status")

# setban and disconnectnode are not divid methods: divid's reply is "Method not found"
both("setban 192.0.2.10 add", "setban", "192.0.2.10", "add")
both("setban 192.0.2.10 add again", "setban", "192.0.2.10", "add")
both("setban of a bad subnet", "setban", "not-a-subnet", "add")
absolute = int(time.time()) + 3600
both("setban 192.0.2.11 add <absolute time>", "setban", "192.0.2.11", "add", absolute, True)
end = next((b.get("banned_until") for b in (I1.call("listbanned")[1] or []) if b.get("address") == "192.0.2.11"),
           None)
iron_row("setban <absolute time>: banned_until", "the time given",
         "the time given" if end is not None and abs(end - absolute) <= 5 else
         "seconds from now" if end is not None and abs(end - (time.time() + absolute)) <= 30 else f"{end}")
both("setban remove of an address not banned", "setban", "192.0.2.12", "remove")
both("disconnectnode of an address not connected", "disconnectnode", UNREACHABLE2)
for n in (I1,):
    n.call("clearbanned")

# ban: divid compares the address given with each peer's "ip:port" text, so it
# never finds a connected peer (net.cpp:395-407); irondivid bans that peer
both("ban of an address with no peer", "ban", "192.0.2.20")
both("ban outdated (none outdated)", "ban", "outdated")
both("ban 127.0.0.1 (node 2's address)", "ban", "127.0.0.1")
time.sleep(2)
both("getconnectioncount (after ban 127.0.0.1)", "getconnectioncount")
both("listbanned (after ban 127.0.0.1)", "listbanned", vary={"banned_until", "ban_created"})
# The ban is kept across a restart only if the node keeps its bans: divid
# keeps them in memory (PeerBanningService.cpp:7-8)
stop_all()
start_all()
time.sleep(5)
both("after restart: listbanned", "listbanned", vary={"banned_until", "ban_created"})
both("after restart: getconnectioncount", "getconnectioncount")
both("clearbanned", "clearbanned")
both("listbanned (after clearbanned)", "listbanned")
need(wait_for(connected, 90), "a pair did not connect again after clearbanned")
replies("after restart: ")

stop_all()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
