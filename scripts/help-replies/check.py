#!/usr/bin/env python3
"""help, help <call> and the usage errors of every call of Divi Core divid and
irondivid, compared.

For every call in divid's command table (rpcserver.cpp:324-467): `help <call>`,
the call with no arguments and with one argument more than divid takes, each
compared exactly where divid answers with text (a help text, an error); where
divid runs the call, only that irondivid runs it too. Then `help` and its list,
and a second pass on nodes started with -disablewallet. Each row prints PASS
(same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. No reply
of a call that runs is printed or written (dumphdinfo's would hold the phrase);
only help texts and errors are.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's reply of the named row is
# changed before it is compared
INJECT = os.environ.get("HELP_REPLIES_INJECT", "")
# A directory to write both replies of every row that is not PASS (for looking
# into a FAIL); nothing is written without it
DUMP = os.environ.get("HELP_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 180

# Differences irondivid has, one per row name, each listed in README.md with
# divid's source line. A KNOWN row that starts to match divid is a FAIL, so the
# list stays true. "open:" rows are gaps not closed yet; "open: rpc-left" rows
# are being closed by fix/rpc-left (RPC-LEFT.md). Rows of the -disablewallet
# pass take the entry of the same row before it.
KNOWN = {
    "help: irondivid's own sections":
        "by design: irondivid has more calls than divid, and lists them after divid's sections under \"<category> (irondivid)\" sections; divid's sections are compared exactly in the row before",
    "removevault with 2 arguments (one too many)":
        "by design: irondivid still takes the second argument older IronDivi callers send, as scripts/vault-replies lists it; divid takes exactly one (rpcwallet.cpp:1194)",
}
# KNOWN rows of the wallet pass only: without a wallet both nodes refuse the
# call before counting its arguments (rpcserver.cpp:1043-1047)
WALLET_PASS_ONLY = {"removevault with 2 arguments (one too many)"}
# Every "help <call> (a call only irondivid has)" row: divid answers "help: unknown
# command" (rpcserver.cpp:283-285), irondivid with the call's help
ONLY_IRONDIVID = "by design: a call only irondivid has; divid answers \"help: unknown command: <call>\" (rpcserver.cpp:283-285)"

# Fields irondivid adds to a reply on purpose: compared without them, and named
# once per call in a "<method>: fields divid lacks" row
EXTRA = {}
extra_seen = {}

fails = 0


def known(name):
    if name.endswith("(a call only irondivid has)"):
        return ONLY_IRONDIVID
    if name in KNOWN:
        return KNOWN[name]
    if name.startswith("disablewallet: "):
        rest = name.split(": ", 1)[1]
        return None if rest in WALLET_PASS_ONLY else KNOWN.get(rest)
    return None


def row(name, core, iron, same):
    global fails
    reason = known(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={core}  irondivid={iron}{note}"[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"replies{index}:{password}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser=replies{index}", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0", "txindex=1",
        ] + list(extra_conf)
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.log = None
        self.start()

    def start(self):
        self.log = open(os.path.join(WORK, self.name + ".out"), "a")
        env = dict(os.environ, **self.env) if self.env else None
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir, env=env,
                                     stdout=self.log, stderr=subprocess.STDOUT, start_new_session=True)
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read(), parse_float=str)
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}", parse_float=str)
        except (OSError, ValueError) as e:
            # No reply at all (the node stopped or closed the connection): a row
            # that differs, not the end of the run
            return ("err", "no reply", f"{type(e).__name__}: {e}"[:120])
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {out[2][:120]}")
        return out[1]

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

    def stop(self):
        try:
            self.call("stop")
        except Exception:
            pass
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


# --- how replies are compared ------------------------------------------------------

def strip(v, drop):
    if isinstance(v, dict):
        return {k: strip(x, drop) for k, x in v.items() if k not in drop}
    if isinstance(v, list):
        return [strip(x, drop) for x in v]
    return v


def kind(v):
    return {dict: "object", list: "array", str: "string", bool: "bool", int: "int", type(None): "null"}.get(type(v), "?")


def first_difference(a, b, path="$"):
    """Where two replies first differ, or None. Reals are compared as divid writes
    them (the text of the number); a real and an integer are different types."""
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k} only on irondivid"
            if k not in b:
                return f"{path}.{k} missing on irondivid"
            d = first_difference(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return f"{path} has {len(a)} items on divid, {len(b)} on irondivid"
        for n, (x, y) in enumerate(zip(a, b)):
            d = first_difference(x, y, f"{path}[{n}]")
            if d:
                return d
        return None
    if type(a) is not type(b):
        return f"{path}: {kind(a)} {json.dumps(a)[:40]} vs {kind(b)} {json.dumps(b)[:40]}"
    if a != b:
        return f"{path}: {json.dumps(a)[:60]} vs {json.dumps(b)[:60]}"
    return None


def short(out):
    if out[0] == "err":
        text = out[2][:80].replace("\n", "\\n")
        return f"error {out[1]} \"{text}\""
    v = out[1]
    if isinstance(v, list):
        return f"{len(v)} items"
    if isinstance(v, dict):
        return f"{len(v)} fields"
    return json.dumps(v)[:60]


def inject(v):
    """A small change to a reply, for the drift proof"""
    if isinstance(v, dict):
        return dict(v, injected=True)
    if isinstance(v, list):
        return v + ["injected"]
    if isinstance(v, int) and not isinstance(v, bool):
        return v + 1
    return "injected"


# divid's help examples name sample addresses and hashes; irondivid's texts
# write them "diviaddress" and "hash" (no address or hash of anyone's wallet is
# written in the tree). Both replies are compared, printed and dumped with that
# done, so no sample address reaches the output either.
SAMPLE_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{40,}(?![0-9A-Za-z])")
SAMPLE_B58 = re.compile(r"(?<![0-9A-Za-z])(?=[1-9A-HJ-NP-Za-km-z]*\d)(?=[1-9A-HJ-NP-Za-km-z]*[A-Za-z])"
                 r"[1-9A-HJ-NP-Za-km-z]{26,35}(?![0-9A-Za-z])")


def samples(text):
    return SAMPLE_B58.sub("diviaddress", SAMPLE_HEX.sub("hash", text))


def normalised(out):
    if out[0] == "err":
        return ("err", out[1], samples(out[2]) if isinstance(out[2], str) else out[2])
    return ("ok", samples(out[1])) if isinstance(out[1], str) else out


def compare(name, core, iron, drop=frozenset(), order=None):
    core, iron = normalised(core), normalised(iron)
    """Same outcome (a result, or an error with the same code and message); for a
    result the same fields, types and values (except `drop`), list items in
    divid's order unless `order` gives a sort key"""
    if INJECT and INJECT == name:
        iron = ("ok", inject(iron[1])) if iron[0] == "ok" else ("err", iron[1], iron[2] + " injected")
    if core[0] == "err" or iron[0] == "err":
        same = core[0] == iron[0] and core[1:] == iron[1:]
        if DUMP and not same:
            dump(name, core, iron)
        row(name, short(core), short(iron), same)
        return
    a, b = strip(core[1], drop), strip(iron[1], drop)
    if order and isinstance(a, list) and isinstance(b, list):
        a, b = sorted(a, key=order), sorted(b, key=order)
    d = first_difference(a, b)
    if d and DUMP:
        dump(name, ("ok", a), ("ok", b))
    row(name, short(core), d or short(iron), d is None)


def dump(name, core, iron):
    safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
    with open(os.path.join(DUMP, safe + ".json"), "w") as f:
        json.dump({"divid": core, "irondivid": iron}, f, indent=1, sort_keys=True)


def both(name, method, *params, **kw):
    core, iron = C.call(method, *params), I.call(method, *params)
    extra = EXTRA.get(method)
    if extra and iron[0] == "ok":
        found = set(fields_in(iron[1])) & extra
        when = name.split(": ", 1)[0] if name.startswith("after restart: ") else ""
        extra_seen.setdefault(when, {}).setdefault(method, set()).update(found)
        iron = ("ok", strip(iron[1], extra))
    compare(name, core, iron, **kw)


def fields_in(v):
    """Every member name in a reply, at any depth"""
    if isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from fields_in(x)
    elif isinstance(v, list):
        for x in v:
            yield from fields_in(x)


def extra_rows(when):
    p = f"{when}: " if when else ""
    for method in EXTRA:
        found = extra_seen.get(when, {}).get(method, set())
        row(f"{p}{method}: fields divid lacks", "-", ",".join(sorted(found)) or "-", not found)


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


def setup_failed(kind_, value, tb):
    # A setup call that fails ends the run with one FAIL line instead of a traceback
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


def synced():
    return wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 90)


def seen_by(node, txid):
    return wait_for(lambda: txid in node.rpc("getrawmempool"), 60)


B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = B58[r] + s
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + s


# --- divid's command table (rpcserver.cpp:324-467) and its argument counts -----------

# Each call's (fewest, most) arguments, from its `if (fHelp || params.size() ...)`
# check; None: no most (listsinceblock checks fHelp only; signtransactionwithaddresskey
# `fHelp || false`). walletlock, walletpassphrase and walletpassphrasechange check
# their counts only on an encrypted wallet, encryptwallet only on an unencrypted
# one; these nodes' wallets are unencrypted. Lines in README.md.
COUNTS = {
    "getinfo": (0, 0), "help": (0, 1), "stop": (0, 1),
    "getnetworkinfo": (0, 0), "addnode": (2, 2), "getaddednodeinfo": (1, 2), "getconnectioncount": (0, 0),
    "getnettotals": (0, 0), "getpeerinfo": (0, 0), "ping": (0, 0),
    "getblockchaininfo": (0, 0), "getbestblockhash": (0, 0), "getblockcount": (0, 0),
    "getlotteryblockwinners": (0, 1), "getblock": (1, 2), "getblockhash": (1, 1), "getblockheader": (1, 2),
    "getchaintips": (0, 0), "getdifficulty": (0, 0), "getmempoolinfo": (0, 0), "getrawmempool": (0, 1),
    "gettxout": (2, 3), "gettxoutsetinfo": (0, 0), "verifychain": (0, 2), "reverseblocktransactions": (1, 1),
    "invalidateblock": (1, 1), "reconsiderblock": (1, 1), "getinvalid": (0, 1),
    "getmininginfo": (0, 0), "prioritisetransaction": (3, 3), "setgenerate": (1, 1), "generateblock": (0, 1),
    "createrawtransaction": (2, 2), "decoderawtransaction": (1, 1), "decodescript": (1, 1),
    "getrawtransaction": (1, 2), "sendrawtransaction": (1, 2), "signtransactionwithaddresskey": (0, None),
    "signrawtransaction": (1, 4),
    "createmultisig": (2, 2), "validateaddress": (1, 1), "verifymessage": (3, 3), "setmocktime": (1, 1),
    "listmasternodes": (0, 1), "getmasternodecount": (0, 0), "setupmasternode": (5, 6),
    "signmnbroadcast": (1, 1), "verifymasternodesetup": (4, 4), "broadcaststartmasternode": (1, 2),
    "startmasternode": (1, 2), "getmasternodestatus": (0, 0), "getmasternodewinners": (0, 3),
    "importmnbroadcast": (1, 1), "listmnbroadcasts": (0, 0), "mnsync": (1, 1), "spork": (1, 2),
    "ban": (1, 1), "clearbanned": (0, 1), "listbanned": (0, 1),
    "addmultisigaddress": (2, 3), "backupwallet": (1, 1), "dumpprivkey": (1, 1), "dumphdinfo": (0, 0),
    "bip38paperwallet": (1, 1), "bip38decrypt": (2, 2), "encryptwallet": (1, 1),
    "getaccountaddress": (1, 1), "getaccount": (1, 1), "getaddressesbyaccount": (1, 1), "getbalance": (0, 3),
    "getnewaddress": (0, 1), "getrawchangeaddress": (0, 1), "getreceivedbyaccount": (1, 2),
    "getreceivedbyaddress": (1, 2), "getstakingstatus": (0, 0), "gettransaction": (1, 2),
    "getunconfirmedbalance": (0, 0), "getwalletinfo": (0, 0), "loadwallet": (1, 1), "importprivkey": (1, 3),
    "importaddress": (1, 3), "keypoolrefill": (0, 1), "listaccounts": (0, 2), "listlockunspent": (0, 0),
    "listreceivedbyaccount": (0, 3), "listreceivedbyaddress": (0, 3), "listsinceblock": (0, None),
    "listtransactions": (0, 4), "listunspent": (0, 3), "lockunspent": (1, 2), "sendfrom": (3, 5),
    "sendmany": (2, 4), "sendtoaddress": (2, 5), "fundvault": (1, 2), "reclaimvaultfunds": (2, 5),
    "debitvaultbyname": (3, 4), "removevault": (1, 1), "addvault": (2, 2), "getcoinavailability": (0, 1),
    "setaccount": (1, 2), "signmessage": (2, 4), "walletlock": (0, None), "walletpassphrasechange": (0, None),
    "walletpassphrase": (0, None),
    "allocatefunds": (3, 3), "getaddressbalance": (1, 2), "getaddressdeltas": (1, 2), "getaddresstxids": (1, 2),
    "getaddressutxos": (1, 2), "getspentinfo": (1, 1),
}
# The "wallet" category of the table (rpcserver.cpp:420-466)
WALLET_CALLS = set("""addmultisigaddress backupwallet dumpprivkey dumphdinfo bip38paperwallet bip38decrypt
encryptwallet getaccountaddress getaccount getaddressesbyaccount getbalance getnewaddress getrawchangeaddress
getreceivedbyaccount getreceivedbyaddress getstakingstatus gettransaction getunconfirmedbalance getwalletinfo
loadwallet importprivkey importaddress keypoolrefill listaccounts listlockunspent listreceivedbyaccount
listreceivedbyaddress listsinceblock listtransactions listunspent lockunspent sendfrom sendmany sendtoaddress
fundvault reclaimvaultfunds debitvaultbyname removevault addvault getcoinavailability setaccount signmessage
walletlock walletpassphrasechange walletpassphrase""".split())
# Arguments for the "one too many" forms: "x" unless a value that cannot do anything
# if a call took them is needed (no file is written, no wallet encrypted)
FILLER = {
    "backupwallet": "/nonexistent/help-replies/x", "dumpprivkey": "x",
    "encryptwallet": "",
}
# Forms not called: divid 3.0.0 stops (the process ends) on them
NOT_CALLED = {("getlotteryblockwinners", 0), ("signtransactionwithaddresskey", 0),
              ("verifymasternodesetup", 0), ("verifymasternodesetup", 5)}
# Calls that take a word first: `<call> help`
SUBCOMMANDS = {"mnsync": ["help"], "spork": ["help"], "getinvalid": ["help"], "addnode": ["x", "help"]}


def too_many(method):
    lo, hi = COUNTS[method]
    if hi is None:
        return None
    return [FILLER.get(method, "x")] * (hi + 1)


def outcome(name, method, *params):
    """Where divid answers with text (a help text or an error), irondivid must
    answer the same code and text; where divid runs the call, irondivid must run it
    too. The reply of a call that runs is not compared, printed or written."""
    core = normalised(C.call(method, *params))
    if core[0] == "err" and core[1] == "no reply":
        print(f"FAIL   divid stopped on {name}: add the form to NOT_CALLED", flush=True)
        sys.exit(1)
    iron = normalised(I.call(method, *params))
    if INJECT and INJECT == name:
        iron = ("err", -1, "injected") if iron[0] == "ok" else ("err", iron[1], iron[2] + " injected")
    if core[0] == "ok" and iron[0] == "ok":
        row(name, "a result", "a result", True)
        return
    same = core[0] == iron[0] and core[1:] == iron[1:]
    if DUMP and not same:
        # only errors and help texts are written, never a result
        dump(name, core if core[0] == "err" else ("ok", "<a result>"),
             iron if iron[0] == "err" else ("ok", "<a result>"))
    row(name, short(core) if core[0] == "err" else "a result",
        short(iron) if iron[0] == "err" else "a result", same)


def help_list(text):
    """The calls a help list names, by section"""
    calls, section = [], ""
    for line in text.split("\n"):
        if line.startswith("== "):
            section = line.strip("= ")
        elif line.strip():
            calls.append((section, line.split(" ", 1)[0]))
    return calls


def own_sections(text):
    """irondivid's list: divid's sections, then its own calls under sections
    named "<category> (irondivid)"; (the first part, the own calls)"""
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if line.startswith("== ") and line.endswith(" (irondivid) =="):
            head = "\n".join(lines[:i]).rstrip("\n")
            own = [l.split(" ", 1)[0] for l in lines[i:] if l.strip() and not l.startswith("== ")]
            return head, own
    return text, []


def help_rows(p, calls, last=True):
    core, iron = C.call("help"), I.call("help")
    if core[0] == iron[0] == "ok":
        head, own = own_sections(iron[1])
        compare(f"{p}help (the list): divid's sections", core, ("ok", head))
        names_a = [n for _, n in help_list(core[1])]
        names_b = [n for _, n in help_list(head)]
        missing = [n for n in names_a if n not in names_b]
        row(f"{p}help: calls divid lists that irondivid does not", "-", ",".join(missing) or "-", not missing)
        row(f"{p}help: irondivid's own sections", "-", ",".join(own) or "-", not own)
        extra_calls.update(own)
    else:
        compare(f"{p}help (the list): divid's sections", core, iron)
    both(f"{p}help nosuchcall", "help", "nosuchcall")
    both(f"{p}help with two arguments", "help", "getinfo", "x")
    for method in calls:
        both(f"{p}help {method}", "help", method)
    for method in calls:
        if method == "stop" or (method == "help"):
            continue
        if (method, 0) not in NOT_CALLED:
            outcome(f"{p}{method} with no arguments", method)
        args = too_many(method)
        if args is not None and (method, len(args)) not in NOT_CALLED:
            outcome(f"{p}{method} with {len(args)} arguments (one too many)", method, *args)
        for sub in [SUBCOMMANDS[method]] if method in SUBCOMMANDS else []:
            outcome(f"{p}{method} {' '.join(sub)}", method, *sub)
    # calls irondivid has that divid does not: divid knows nothing of them
    for method in sorted(extra_calls):
        both(f"{p}help {method} (a call only irondivid has)", "help", method)
    if last:
        outcome(f"{p}stop with 2 arguments (one too many)", "stop", "x", "x")
        outcome(f"{p}stop with no arguments", "stop")


extra_calls = set()

# --- the nodes -----------------------------------------------------------------------


def start_nodes(extra):
    global C, I
    C = Node("divid" + extra.get("suffix", ""), DIVID, 0, ["listen=1"] + extra.get("conf", []))
    if not C.wait_ready():
        print(f"FAIL   start: divid did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)
    I = Node("irondivid" + extra.get("suffix", ""), IRONDIVID, 1,
             ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"] + extra.get("conf", []))
    if not I.wait_ready():
        print(f"FAIL   start: irondivid did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)


def stop_nodes():
    for n in (C, I):
        if n.proc.poll() is None:
            n.stop()
        else:
            n.log.close()


start_nodes({})
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}", flush=True)
C.rpc("setgenerate", 5)
synced()
CALLS = list(COUNTS)
help_rows("", CALLS)
stop_nodes()

# Second pass: both nodes without a wallet
start_nodes({"suffix": "-nowallet", "conf": ["disablewallet=1"]})
wallet_calls = [m for m in CALLS if m in WALLET_CALLS]
help_rows("disablewallet: ", ["help", "getinfo"] + wallet_calls)
stop_nodes()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
