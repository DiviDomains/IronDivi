#!/usr/bin/env python3
"""Labels, comments and messages of odd text in Divi Core divid's wallet and in
irondivid's, side by side on one regtest chain: non-ASCII (accents, CJK,
emoji), the empty string, long strings, quotes and backslashes, tabs, newlines
and NUL, and strings that look like numbers or JSON.

Three nodes: S, a divid that mines and pays; C, a divid wallet; I, an irondivid
wallet. C and I are separate wallets; each gets the same calls with the same
text, and their replies are compared: the text read back (decoded), the JSON
text of the reply (its escaping), and error codes and messages. The text goes
in as UTF-8 JSON, and for non-ASCII text also as \\u escapes (what Python's
json.dumps and many tools send). Then each wallet restarts, and each is copied
with backupwallet and a fresh node started on the copy; the text must read back
the same. Each row prints PASS (same as divid), KNOWN (a difference listed in
README.md) or FAIL. Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes.
"""

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "lib"))
import node_ports  # noqa: E402  (scripts/lib: a node whose ports were taken starts again on new ones)

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
IRON_CLI = os.path.join(os.path.dirname(IRONDIVID), "irondivi-cli")
DIVI_CLI = os.path.join(os.path.dirname(DIVID), "divi-cli")
INJECT = os.environ.get("ODD_TEXT_INJECT", "")
HOST = "127.0.0.2"
RPC_TIMEOUT = 120
START_TIMEOUT = 300

# The text cases: name -> text. Each goes in as UTF-8 JSON; those in ESCAPED
# also as \u escapes.
CASES = {
    "ascii": "plain label",
    "accents": "café Ünïcödé ñ",
    "cjk": "中文标签 日本語",
    "emoji": "💰🚀 coins",
    "empty": "",
    "long 300": "L" * 150 + "é" * 75 + "x" * 75,
    "long 5000": ("abcdefghij" * 500),
    "quotes": 'say "hi" \'x\' back\\slash /',
    "tab newline": "a\tb\nc\rd",
    "nul": "a\x00b",
    "control": "bell\x07 esc\x1b del\x7f",
    "number": "123",
    "float": "1e5",
    "json object": '{"a": 1}',
    "json null": "null",
    "spaces": "  padded  ",
    "star": "*",
}
ESCAPED = {"accents", "cjk", "emoji", "long 300"}
NO_ARGV = {"nul"}  # argv cannot carry NUL

# Differences listed in README.md: (which rows, reason, shape). shape takes the
# two values and is true only for the difference described, so a KNOWN row
# that differs in another way is a FAIL.


def low_bytes(t):
    """What divid keeps of text sent as \\u escapes: its JSON reader stores the
    low byte of each escape (json_spirit_reader_template.h, hex_str_to_char),
    one per UTF-16 unit, read back through its writer"""
    units = t.encode("utf-16-be")
    kept = "".join(chr(units[k + 1]) for k in range(0, len(units), 2))
    return undo_byte_escapes(kept)


def decoded(j):
    try:
        return undo_byte_escapes(json.loads(j, strict=False)) if isinstance(j, str) else j
    except ValueError:
        return j


ESCAPING = ("the same text, escaped otherwise: divid's json_spirit writer writes each byte that is not iswprint in "
            "the C locale (every byte >= 0x80 of UTF-8 text, and DEL) as \\u00XX in capitals, so non-ASCII text "
            "comes back one character per byte (json_spirit_writer_template.h:64-90); irondivid writes the UTF-8 "
            "text and escapes what JSON requires")
LOW_BYTE = ("divid's JSON reader keeps only the low byte of a \\u escape above \\u00FF "
            "(json_spirit_reader_template.h:hex_str_to_char), so the text is cut down before it is stored; "
            "irondivid stores the text sent")
LATIN1 = ("divid's JSON reader stores \\u00E9 as the single byte E9, not as UTF-8, so it signs other bytes than "
          "the text's UTF-8 (json_spirit_reader_template.h:hex_str_to_char); each node verifies only its own")
CROSS = lambda c, i: c == [{"ok": True}, {"ok": False}] and i == [{"ok": False}, {"ok": True}]
NO_CHAIN = ("irondivid's wallet keeps a confirmed transaction as a record that points into the chain database, "
            "where divid's wallet.dat holds the whole transaction; on a node started on the backup without the "
            "chain, gettransaction cannot read it until the block is there (docs/divid-differences.md W3). The "
            "labels and comments are on the copy: the rows after it syncs compare them")
GONE = {"error": -5, "message": "Invalid or non-wallet transaction id"}
WITHOUT_CHAIN = lambda c, i: c == {} and bool(i) and all(
    k.startswith("gettransaction ") and v[1] == GONE for k, v in i.items())
KNOWN = [(lambda n: n.endswith(": JSON text"), ESCAPING, lambda c, i: decoded(c) == decoded(i)),
         (lambda n: n.startswith("on the backupwallet copy, no chain yet:"), NO_CHAIN, WITHOUT_CHAIN)]
for _name in ("accents", "long 300"):
    KNOWN.append((lambda n, p=f"{_name} (escaped): verifymessage": n.startswith(p), LATIN1, CROSS))

fails = 0


def known(name):
    return next(((r, sh) for match, r, sh in KNOWN if match(name)), None)


fails = 0


def show(v):
    return json.dumps(v, ensure_ascii=True, sort_keys=True, default=str)[:240]


def row(name, core, iron, same=None):
    global fails
    if same is None:
        same = core == iron
    if INJECT and INJECT == name:
        same = False
        iron = ("injected", iron)
    listed = known(name)
    if listed:
        reason, shape = listed
        if same and reason in (ESCAPING, NO_CHAIN):
            word, note = "PASS", ""  # text that needs no other escaping
        elif same:
            word, note = "FAIL", "  [listed as KNOWN but now matches divid: update README.md]"
        elif shape(core, iron):
            word, note = "KNOWN", "  [known: " + reason + "]"
        else:
            word, note = "FAIL", "  [listed as KNOWN, but differs in another way]"
    else:
        word, note = ("PASS", "") if same else ("FAIL", "")
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={show(core)}  irondivid={show(iron)}{note}", flush=True)


def undo_byte_escapes(v):
    """divid's JSON writer escapes each byte >= 0x80 of its UTF-8 text as its own
    \\u00XX (json_spirit_writer_template.h:64-90, iswprint in the C locale), so
    a reply decodes to one character per byte. This gives the text back; a
    string whose bytes are no UTF-8 stays as it is."""
    if isinstance(v, str):
        try:
            return v.encode("latin-1").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return v
    if isinstance(v, list):
        return [undo_byte_escapes(x) for x in v]
    if isinstance(v, dict):
        return {undo_byte_escapes(k): undo_byte_escapes(x) for k, x in v.items()}
    return v


class Node:
    def __init__(self, name, binary, index, extra_conf, datadir=None):
        self.name, self.binary = name, binary
        self.p2p, self.rpcport = PORT_BASE + 2 * index, PORT_BASE + 2 * index + 1
        self.dir = datadir or os.path.join(WORK, name)
        self.password = secrets.token_hex(16)
        self.user = "odd" + name.replace("-", "")
        self.auth = base64.b64encode(f"{self.user}:{self.password}".encode()).decode()
        os.makedirs(self.dir, exist_ok=True)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", f"rpcuser={self.user}",
            f"rpcpassword={self.password}", f"rpcbind={HOST}", "rpcallowip=127.0.0.0/8", f"bind={HOST}",
            f"rpcconnect={HOST}", "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "dnsseed=0", "staking=0",
        ] + list(extra_conf)
        self.conf = os.path.join(self.dir, "divi.conf")
        fd = os.open(self.conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self, *args):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}", *args], cwd=self.dir,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True, work=WORK)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def post(self, body):
        """The raw reply body for a raw request body"""
        req = urllib.request.Request(f"http://{HOST}:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except (ConnectionError, urllib.error.URLError, OSError) as e:
            raise RuntimeError(f"{self.name}: {e}") from None

    def call(self, method, *params, escaped=False):
        """('ok', result, raw reply) or ('err', code, message, raw reply)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)},
                          ensure_ascii=escaped).encode("utf-8")
        status, raw = self.post(body)
        try:
            reply = json.loads(raw.decode("utf-8", errors="surrogateescape"), strict=False)
        except ValueError:
            return ("err", f"http {status}", raw[:200].decode("latin-1"), raw)
        if reply is None:
            return ("err", f"http {status}", "null reply", raw)
        if self.binary == DIVID:
            reply = undo_byte_escapes(reply)
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""), raw)
        return ("ok", reply.get("result"), raw)

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:120]}")
        return out[1]

    def cli(self, cli, *args):
        """(exit code, stdout bytes, stderr bytes) of the node's CLI"""
        p = subprocess.run([cli, f"-datadir={self.dir}", *args], capture_output=True, timeout=120)
        return p.returncode, p.stdout, p.stderr

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            try:
                if self.call("getblockcount")[0] == "ok":
                    return True
            except Exception:
                pass
            time.sleep(0.5)
        return False

    def tail(self, n=4):
        lines = []
        for path in (os.path.join(WORK, self.name + ".out"), os.path.join(self.dir, "regtest", "debug.log")):
            try:
                with open(path, errors="replace") as f:
                    lines += [l.strip() for l in f.readlines() if "rror" in l or "panic" in l][-n:]
            except OSError:
                pass
        return " | ".join(lines)[-500:]

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=90)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()

    def restart(self, *args):
        self.stop()
        self.start(*args)
        if not self.wait_ready():
            raise RuntimeError(f"{self.name} did not answer after a restart: {self.tail()}")


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


def setup_failed(kind, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    for n in globals().get("NODES", ()):
        t = n.tail()
        if t:
            print(f"#      {n.name}: {t}"[:700], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed

S = Node("divid-miner", DIVID, 0, ["listen=1"])
if not S.wait_ready():
    print(f"FAIL   start: divid miner did not answer: {S.tail()}", flush=True)
    sys.exit(1)
C = Node("divid-wallet", DIVID, 1, ["listen=0", f"connect={HOST}:{S.p2p}"])
I = Node("irondivid-wallet", IRONDIVID, 2, ["listen=0", f"connect={HOST}:{S.p2p}"])
for n in (C, I):
    if not n.wait_ready():
        print(f"FAIL   start: {n.name} did not answer: {n.tail()}", flush=True)
        sys.exit(1)
NODES = [S, C, I]
TWINS = (C, I)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)


def synced(secs=120):
    return wait_for(lambda: len({n.rpc("getbestblockhash") for n in NODES}) == 1, secs)


def mine(n=1):
    for _ in range(n):
        out = S.call("setgenerate", 1)
        if out[0] != "ok":
            tip = S.rpc("getblock", S.rpc("getbestblockhash"))
            wait_for(lambda: time.time() > tip["time"] + 1, 60)
            S.rpc("setgenerate", 1)
    if not synced():
        raise RuntimeError("the nodes did not follow the chain")


# --- how a reply is shown ---------------------------------------------------------

def outcome(out, value=lambda v: v):
    """A reply as compared: the decoded value (through value), or the error"""
    if out[0] == "err":
        return {"error": out[1], "message": out[2]}
    return {"ok": value(out[1])}


def json_text(out):
    """The JSON text of a string result, as the node wrote it"""
    if out[0] != "ok" or not isinstance(out[1], str):
        return outcome(out)
    raw = out[2].decode("utf-8", errors="backslashreplace")
    i = raw.find('"result"')
    j = raw.find(':', i) + 1
    while raw[j] in " \t":
        j += 1
    if raw[j] != '"':
        return raw[j:j + 40]
    k = j + 1
    while raw[k] != '"':
        k += 2 if raw[k] == "\\" else 1
    return raw[j:k + 1]


def text_of(v):
    """A decoded text, short enough to print: its length and code points"""
    if not isinstance(v, str):
        return v
    return v if len(v) <= 60 else f"{v[:30]}...{v[-10:]} ({len(v)} chars)"


def amount(v):
    return None if v is None else round(float(v), 8)


# --- the cases ----------------------------------------------------------------------

mine(110)
PAYEE = S.rpc("getnewaddress")
for n in TWINS:
    S.rpc("sendtoaddress", n.rpc("getnewaddress"), 500)
mine(1)
mine(1)

state = {}  # (node name, case) -> what the restart and the copy are checked against


def labels(name, t, escaped):
    """Address-book calls with text t on both wallets"""
    tag = f"{name}{' (escaped)' if escaped else ''}"
    got = {}
    for n in TWINS:
        r = {}
        r["getnewaddress"] = n.call("getnewaddress", t, escaped=escaped)
        a = r["getnewaddress"][1] if r["getnewaddress"][0] == "ok" else None
        b = n.rpc("getnewaddress")
        r["setaccount"] = n.call("setaccount", b, t, escaped=escaped)
        if a:
            r["getaccount new"] = n.call("getaccount", a)
        r["getaccount set"] = n.call("getaccount", b)
        r["getaddressesbyaccount"] = n.call("getaddressesbyaccount", t, escaped=escaped)
        r["getaccountaddress"] = n.call("getaccountaddress", t, escaped=escaped)
        got[n.name] = (r, a, b)
    (rc, ac, bc), (ri, ai, bi) = got[C.name], got[I.name]
    row(f"{tag}: getnewaddress", outcome(rc["getnewaddress"], lambda v: "address"),
        outcome(ri["getnewaddress"], lambda v: "address"))
    row(f"{tag}: setaccount", outcome(rc["setaccount"]), outcome(ri["setaccount"]))
    for k in ("getaccount new", "getaccount set"):
        if k in rc or k in ri:
            c, i = rc.get(k, ("err", "-", "not run", b"")), ri.get(k, ("err", "-", "not run", b""))
            row(f"{tag}: {k}: text read back", outcome(c, text_of), outcome(i, text_of))
            row(f"{tag}: {k}: same as given", c[0] == "ok" and c[1] == t, i[0] == "ok" and i[1] == t)
            row(f"{tag}: {k}: JSON text", json_text(c), json_text(i))
    mine_ = lambda r, a, b: outcome(r["getaddressesbyaccount"], lambda v: sorted(
        {a: "new", b: "set"}.get(x, "other") for x in v))
    row(f"{tag}: getaddressesbyaccount", mine_(rc, ac, bc), mine_(ri, ai, bi))
    row(f"{tag}: getaccountaddress", outcome(rc["getaccountaddress"], lambda v: {ac: "new", bc: "set"}.get(v, "another")),
        outcome(ri["getaccountaddress"], lambda v: {ai: "new", bi: "set"}.get(v, "another")))
    return {C.name: ac or bc, I.name: ai or bi}


def accounts_view(n, t):
    """What the account calls say about account t"""
    v = {}
    if t == "*":
        un = n.rpc("listunspent", 0)
        print(f"#      {n.name} at the star case: getbalance {n.rpc('getbalance')}, unconfirmed "
              f"{n.rpc('getunconfirmedbalance')}, listunspent 0 sum {round(sum(float(u['amount']) for u in un), 8)} "
              f"({len(un)} coins, {sum(1 for u in un if u.get('confirmations', 0) == 0)} unconfirmed), "
              f"locked {len(n.rpc('listlockunspent'))}", flush=True)
    la = n.call("listaccounts", 0)
    v["listaccounts"] = outcome(la, lambda d: {"has it": t in d, "balance": amount(d.get(t))})
    lr = n.call("listreceivedbyaccount", 0, True)
    v["listreceivedbyaccount"] = outcome(lr, lambda l: [
        {"amount": amount(e.get("amount")), "confirmations": e.get("confirmations")}
        for e in l if e.get("account") == t])
    v["getreceivedbyaccount"] = outcome(n.call("getreceivedbyaccount", t, 0), amount)
    v["getbalance"] = outcome(n.call("getbalance", t, 0), amount)
    return v


def tx_text(n, txid):
    out = n.call("gettransaction", txid)
    return outcome(out, lambda t: {k: text_of(t.get(k)) for k in ("comment", "to")} | {
        "details accounts": sorted((text_of(d.get("account")) for d in t.get("details", [])), key=show)})


def list_view(n, t):
    out = n.call("listtransactions", t, 100)
    return outcome(out, lambda l: sorted(
        ((e.get("category"), text_of(e.get("account")), text_of(e.get("comment")), text_of(e.get("to")),
          amount(e.get("amount"))) for e in l), key=show))



def signs(name, t, escaped, tag):
    """signmessage: each signs, each checks its own and the other's"""
    sig = {}
    for n in TWINS:
        a = addresses[(name, escaped)][n.name]
        sig[n.name] = (a, n.call("signmessage", a, t, escaped=escaped))
    row(f"{tag}: signmessage", outcome(sig[C.name][1], lambda v: "signature"),
        outcome(sig[I.name][1], lambda v: "signature"))
    if sig[C.name][1][0] == "ok" and sig[I.name][1][0] == "ok":
        for checker in TWINS:
            got = []
            for signer in TWINS:
                a, s = sig[signer.name][0], sig[signer.name][1][1]
                got.append(outcome(checker.call("verifymessage", a, s, t, escaped=escaped)))
            state.setdefault((checker.name, tag), {})["verify"] = got
        row(f"{tag}: verifymessage of divid's and irondivid's signature",
            state[(C.name, tag)]["verify"], state[(I.name, tag)]["verify"])


# The escaped cases get their own text, so each is an account of its own
plan = [(name, t, False) for name, t in CASES.items()] + [(name, t + " (escaped)", True)
                                                          for name, t in CASES.items() if name in ESCAPED]
# Values that are no text at all, where the calls take text: JSON null and a JSON number
VALUES = {"null value": None, "number value": 123}
plan += [(name, v, False) for name, v in VALUES.items()]

for _name, _t, _escaped in plan:
    if _escaped and _name in ("cjk", "emoji"):
        _p = f"{_name} (escaped): "
        _cut = low_bytes(_t)
        KNOWN[:0] = [
            (lambda n, p=_p: n.startswith(p) and n.endswith(": text read back"), LOW_BYTE,
             lambda c, i, cut=_cut, t=_t: c == {"ok": text_of(cut)} and i == {"ok": text_of(t)}),
            (lambda n, p=_p: n.startswith(p) and n.endswith(": same as given"), LOW_BYTE,
             lambda c, i: c is False and i is True),
            (lambda n, p=_p: n.startswith(p) and n.endswith(": JSON text"), LOW_BYTE,
             lambda c, i, cut=_cut, t=_t: decoded(c) == cut and decoded(i) == t),
            (lambda n, p=_p: n.startswith(p + "verifymessage"), LOW_BYTE, CROSS),
        ]
addresses = {}
for name, t, escaped in plan:
    addresses[(name, escaped)] = labels(name, t, escaped)

# Each account gets two coins of 3 DIVI on its address: one for its sendfrom,
# one for its sendmany. The coins of a send are pinned with lockunspent, so
# both wallets spend the same coins and the account balances (credits less the
# account's own coins spent, as divid counts them) compare exactly.
for (name, escaped), by_node in addresses.items():
    if escaped:
        continue
    for n in TWINS:
        if by_node[n.name]:
            for _ in range(2):
                S.rpc("sendtoaddress", by_node[n.name], 3)
mine(1)
case_coins = {}  # (node, case) -> [outpoint, outpoint]
for n in TWINS:
    unspent = n.rpc("listunspent", 0)
    for (name, escaped), by_node in addresses.items():
        a = by_node[n.name]
        case_coins[(n.name, name, escaped)] = [{"txid": u["txid"], "vout": u["vout"]} for u in unspent
                                               if u.get("address") == a and amount(u["amount"]) == 3.0][:2]


def only(n, coins):
    """Unlock exactly `coins` (all unspent when None) on node n"""
    n.rpc("lockunspent", True)
    if coins is None:
        return
    keep = {(c["txid"], c["vout"]) for c in coins}
    rest = [{"txid": u["txid"], "vout": u["vout"]} for u in n.rpc("listunspent", 0)
            if (u["txid"], u["vout"]) not in keep]
    if rest:
        n.rpc("lockunspent", False, rest)


all_case_coins = {n.name: [c for (node, _, _), cs in case_coins.items() if node == n.name for c in cs]
                  for n in TWINS}

for name, t, escaped in plan:
    tag = f"{name}{' (escaped)' if escaped else ''}"
    if escaped:
        signs(name, t, escaped, tag)
        continue
    views = {n.name: accounts_view(n, t) for n in TWINS}
    for k in views[C.name]:
        row(f"{tag}: {k}", views[C.name][k], views[I.name][k])
    sends = {}
    for n in TWINS:
        s = {}
        coins = case_coins[(n.name, name, escaped)] + [None, None]
        # The default account's send keeps off every account's coins
        n.rpc("lockunspent", True)
        n.rpc("lockunspent", False, all_case_coins[n.name])
        # divid takes the comments after "metadata" (rpcwallet.cpp:1336-1353)
        s["sendtoaddress"] = n.call("sendtoaddress", PAYEE, 0.5, "metadata", t, t, escaped=escaped)
        only(n, coins[:1] if coins[0] else [])
        s["sendfrom"] = n.call("sendfrom", t, PAYEE, 0.25, t, t, escaped=escaped)
        if s["sendfrom"][0] != "ok":
            a = addresses[(name, escaped)][n.name]
            print(f"#      {n.name} {tag} sendfrom: case coins {coins[:2]}, at {a}: "
                  f"{[(u['txid'][:8], u['vout'], u['amount']) for u in n.rpc('listunspent', 0) if u.get('address') == a]}, "
                  f"locked {len(n.rpc('listlockunspent'))}", flush=True)
        only(n, coins[1:2] if coins[1] else [])
        s["sendmany"] = n.call("sendmany", t, {PAYEE: 0.125}, t, escaped=escaped)
        only(n, None)
        sends[n.name] = s
    for k in ("sendtoaddress", "sendfrom", "sendmany"):
        c, i = sends[C.name][k], sends[I.name][k]
        row(f"{tag}: {k}", outcome(c, lambda v: "txid"), outcome(i, lambda v: "txid"))
        tc = tx_text(C, c[1]) if c[0] == "ok" else None
        ti = tx_text(I, i[1]) if i[0] == "ok" else None
        if tc or ti:
            row(f"{tag}: {k}: gettransaction comment, to, accounts", tc, ti)
            for n, tx in ((C, c), (I, i)):
                if tx[0] == "ok":
                    state.setdefault((n.name, tag), {}).setdefault("txids", {})[k] = tx[1]
    # Mined once S has every send of the case, so no change stays unconfirmed
    made = [r[1] for by in sends.values() for r in by.values() if r[0] == "ok"]
    if not wait_for(lambda: set(made) <= set(S.rpc("getrawmempool")), 60):
        raise RuntimeError(f"{tag}: the sends did not reach the miner")
    mine(1)
    for n in TWINS:
        state.setdefault((n.name, tag), {})["listtransactions"] = list_view(n, t)
        state[(n.name, tag)]["accounts"] = accounts_view(n, t)
    row(f"{tag}: listtransactions of the account", state[(C.name, tag)]["listtransactions"],
        state[(I.name, tag)]["listtransactions"])
    signs(name, t, escaped, tag)

mine(1)

# --- the CLIs: the text as an argument ------------------------------------------------------
for name, t in CASES.items():
    if name in NO_ARGV:
        continue
    got = {}
    for n, cli in ((C, DIVI_CLI), (I, IRON_CLI)):
        a = n.rpc("getnewaddress")
        rc, out, err = n.cli(cli, "setaccount", a, t)
        rc2, out2, err2 = n.cli(cli, "getaccount", a)
        back = n.call("getaccount", a)
        got[n.name] = {"setaccount exit": rc, "setaccount stderr": err.decode("utf-8", "backslashreplace")[:120],
                       "getaccount exit": rc2, "getaccount stdout": out2.decode("utf-8", "backslashreplace")[:200],
                       "read back by RPC": outcome(back, text_of)}
    for k in got[C.name]:
        row(f"cli {name}: {k}", got[C.name][k], got[I.name][k])

# --- after a restart, and on a copy made with backupwallet ------------------------------------


def snapshot(orig, n, name, t, escaped, chain=True):
    """What must read back the same: the account's addresses' labels, each saved
    transaction's comment and to, and (with the chain) the account calls"""
    tag = f"{name}{' (escaped)' if escaped else ''}"
    a = addresses[(name, escaped)][orig.name]
    v = {"getaccount": outcome(n.call("getaccount", a), text_of) if a else None,
         "listaccounts has it": outcome(n.call("listaccounts", 0), lambda d: t in d)}
    for k, txid in state.get((orig.name, tag), {}).get("txids", {}).items():
        v[f"gettransaction {k}"] = tx_text(n, txid)
    if chain:
        v["accounts"] = accounts_view(n, t)
        v["listtransactions"] = list_view(n, t)
    return tag, v


before = {(n.name, name, escaped): snapshot(n, n, name, t, escaped)[1] for n in TWINS for name, t, escaped in plan}


def check_again(when, pairs, chain=True):
    for name, t, escaped in plan:
        res = {}
        for orig, n in pairs:
            tag, now = snapshot(orig, n, name, t, escaped, chain)
            was = before[(orig.name, name, escaped)]
            res[orig.name] = {k: (was.get(k), now[k]) for k in sorted(now) if now[k] != was.get(k)}
        row(f"{when}: {tag}: what differs from before (before, now)", res[C.name], res[I.name],
            res[C.name] == res[I.name])


for n in TWINS:
    n.restart()
if not synced():
    raise RuntimeError("the wallets did not reconnect after the restart")
check_again("after a restart", ((C, C), (I, I)))

# backupwallet, then a fresh node on the copy, with no peers and no chain
pairs = []
for n, binary, index in ((C, DIVID, 3), (I, IRONDIVID, 4)):
    dest = os.path.join(WORK, n.name + "-backup")
    row(f"backupwallet ({n.name})", "ok", outcome(n.call("backupwallet", dest), lambda v: "ok").get("ok", "error"))
    newdir = os.path.join(WORK, n.name + "-copy")
    # divid's regtest wallet is regtest/wallet.dat; irondivid's the folder wallet in the datadir
    target = os.path.join(newdir, "regtest", "wallet.dat") if binary == DIVID else os.path.join(newdir, "wallet")
    os.makedirs(os.path.dirname(target))
    if os.path.isdir(dest):
        shutil.copytree(dest, target)
    else:
        shutil.copyfile(dest, target)
    copy = Node(n.name + "-copy", binary, index, ["listen=0", "connect=0"], datadir=newdir)
    if not copy.wait_ready():
        raise RuntimeError(f"{copy.name} did not start on the copy: {copy.tail()}")
    NODES.append(copy)
    pairs.append((n, copy))
check_again("on the backupwallet copy, no chain yet", pairs, chain=False)

# The copies then sync from S and are checked again, with the chain
for orig, copy in pairs:
    copy.stop()
    with open(copy.conf) as f:
        conf = f.read().replace("connect=0", f"connect={HOST}:{S.p2p}")
    with open(copy.conf, "w") as f:
        f.write(conf)
    copy.start()
    if not copy.wait_ready():
        raise RuntimeError(f"{copy.name} did not start again: {copy.tail()}")
if not wait_for(lambda: all(c.rpc("getbestblockhash") == S.rpc("getbestblockhash") for _, c in pairs), 180):
    raise RuntimeError("the copies did not sync")
time.sleep(3)
check_again("on the backupwallet copy, synced", pairs)

# divid 3.0.0 has no dumpwallet, importwallet or move (rpcserver.cpp:410-470)
for method, params in (("dumpwallet", [os.path.join(WORK, "dump.txt")]),
                       ("importwallet", [os.path.join(WORK, "dump.txt")]),
                       ("move", ["", "x", 1, 1, "odd text"])):
    row(f"{method}", outcome(C.call(method, *params)), outcome(I.call(method, *params)))

for n in NODES:
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
