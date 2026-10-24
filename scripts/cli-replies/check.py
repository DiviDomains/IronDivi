#!/usr/bin/env python3
"""What Divi Core's divi-cli and irondivi-cli print, compared.

The same arguments go to both command-line clients against the same node, once
against divid and once against irondivid, and their exit code, stdout and
stderr are compared. Both nodes sit on one regtest chain that divid mines;
irondivid's wallet comes from divid's phrase. Each row prints PASS (irondivi-cli
prints what divi-cli prints), KNOWN (a difference listed in README.md) or FAIL.
Exit code = FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
lives only in memory, in an RPC reply and in irondivid's environment. The RPC
password is made per run for the two throwaway regtest nodes; it is in their
divi.conf, and on a client's command line only in the rows that test
-rpcpassword given there. It is never printed.
"""

import base64
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request

IRON_BIN, CORE_BIN, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
IRONDIVID, IRONCLI = os.path.join(IRON_BIN, "irondivid"), os.path.join(IRON_BIN, "irondivi-cli")
DIVID, DIVICLI = os.path.join(CORE_BIN, "divid"), os.path.join(CORE_BIN, "divi-cli")
# For the proof that a difference is caught: irondivi-cli's output of the named
# row is changed before it is compared
INJECT = os.environ.get("CLI_REPLIES_INJECT", "")
# A directory to write both outputs of every row that is not PASS
DUMP = os.environ.get("CLI_REPLIES_DUMP", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 180
CLI_TIMEOUT = 60
# How often divi-cli's getblockcount is asked of irondivid in the repeat row
REPEATS = int(os.environ.get("CLI_REPLIES_REPEATS", "50"))

# Differences irondivi-cli has, one per row name, each listed in README.md with
# divi-cli's source line. A KNOWN row that starts to match divi-cli is a FAIL, so
# the list stays true. Rows "... on divid" and "... on irondivid" take the entry
# of the row name without the node.
KNOWN = {
    "-stdin, the argument on stdin":
        "irondivi-cli reads more arguments from stdin, as Bitcoin Core's bitcoin-cli -stdin does; divi-cli has no -stdin, skips it as a switch (divi-cli.cpp:140-144) and calls getblockhash with no argument",
    "-named":
        "irondivi-cli sends name=value arguments as named parameters (an object); divi-cli has no -named and sends \"height=1\" as a string. Neither divid nor irondivid takes named parameters (divid: -32600 \"Params must be an array\", rpcserver.cpp:903), so -named is of use only with other servers",
    "--rpcport <port> with a space":
        "irondivi-cli also takes the --name value form (its -help: \"Options may also be written --name value\"); divi-cli reads only -name=value (Settings.cpp:130-151), so the port becomes its call and divi.conf's wrong rpcport stays",
    "-help: text":
        "the version line names the client: \"IronDivi RPC client version v<irondivi version>\" where divi-cli prints \"Divi Core RPC client version v3.0.0\" (divi-cli.cpp:52-65); exit code, stream and the line's shape are compared in the row before",
    "-?: text": "the same as -help: text",
    "no arguments: text": "the same as -help: text",
    "-version: text":
        "the version line names the client, and the license text and the option list are irondivi-cli's own (divi-cli.cpp:53-62, HelpMessageCli)",
}

fails = 0
PASSWORD = secrets.token_hex(16)


def known(name):
    if name in KNOWN:
        return KNOWN[name]
    for suffix in (" on divid", " on irondivid"):
        if name.endswith(suffix):
            return KNOWN.get(name[: -len(suffix)])
    return None


def row(name, core, iron, same):
    global fails
    reason = known(name)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divi-cli: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divi-cli={core}  irondivi-cli={iron}{note}"[:400], flush=True)


class Node:
    def __init__(self, name, binary, index, extra_conf, env=None):
        self.name, self.binary, self.env = name, binary, env
        self.dir = os.path.join(WORK, name)
        self.p2p = PORT_BASE + 2 * index
        self.rpcport = PORT_BASE + 2 * index + 1
        self.user = f"replies{index}"
        self.auth = base64.b64encode(f"{self.user}:{PASSWORD}".encode()).decode()
        os.makedirs(self.dir)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}",
            f"rpcuser={self.user}", f"rpcpassword={PASSWORD}",
            "daemon=0", "printtoconsole=0", "server=1", "discover=0", "listenonion=0",
            "bind=127.0.0.1", "dnsseed=0", "staking=0", "txindex=1",
        ] + list(extra_conf)
        write_private(os.path.join(self.dir, "divi.conf"), lines)
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
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.rpcport}/", data=body,
                                     headers={"Authorization": "Basic " + self.auth, "Content-Type": "text/plain"})
        try:
            with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            reply = json.loads(e.read() or b"{}")
        except (OSError, ValueError) as e:
            return ("err", "no reply", str(e))
        err = reply.get("error")
        if err:
            return ("err", err.get("code"), err.get("message", ""))
        return ("ok", reply.get("result"))

    def rpc(self, method, *params):
        out = self.call(method, *params)
        if out[0] != "ok":
            raise RuntimeError(f"{self.name} {method}: {out[1]} {str(out[2])[:120]}")
        return out[1]

    def wait_ready(self):
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if self.proc.poll() is not None:
                return False
            if self.call("getblockcount")[0] == "ok":
                return True
            time.sleep(0.5)
        return False

    def stop(self):
        self.call("stop")
        try:
            self.proc.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()


def write_private(path, lines):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")


def setup_failed(kind_, value, tb):
    print(f"FAIL   setup: {value}"[:300], flush=True)
    sys.exit(1)


sys.excepthook = setup_failed


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


# --- running the two clients ------------------------------------------------------

def run(binary, args, stdin=""):
    """(exit code, stdout, stderr) of one client run"""
    try:
        p = subprocess.run([binary] + args, input=stdin, capture_output=True, text=True, timeout=CLI_TIMEOUT,
                           cwd=WORK)
        return (p.returncode, p.stdout, p.stderr)
    except subprocess.TimeoutExpired:
        return ("timeout", "", "")


def short(out):
    rc, so, se = out
    text = (so or se).strip().replace("\n", "\\n")
    where = "stdout" if so else ("stderr" if se else "nothing")
    return f"exit {rc}, {where} {json.dumps(text[:70])}"


def first_difference(a, b):
    for what, x, y in (("exit code", a[0], b[0]), ("stdout", a[1], b[1]), ("stderr", a[2], b[2])):
        if x != y:
            if what == "exit code":
                return f"exit {y} (divi-cli {x})"
            lines_a, lines_b = x.split("\n"), y.split("\n")
            for n, (la, lb) in enumerate(zip(lines_a, lines_b)):
                if la != lb:
                    return f"{what} line {n + 1}: {json.dumps(lb[:70])} (divi-cli {json.dumps(la[:70])})"
            return f"{what} has {len(lines_b)} lines (divi-cli {len(lines_a)})"
    return None


def compare(name, core, iron):
    if INJECT and INJECT == name:
        iron = (iron[0], iron[1] + "injected\n", iron[2])
    d = first_difference(core, iron)
    if d and DUMP:
        safe = "".join(ch if ch.isalnum() else "_" for ch in name)[:80]
        with open(os.path.join(DUMP, safe + ".json"), "w") as f:
            json.dump({"divi-cli": core, "irondivi-cli": iron}, f, indent=1)
    row(name, short(core), d or short(iron), d is None)


def both(name, args, stdin=""):
    """The same arguments to divi-cli and irondivi-cli"""
    compare(name, run(DICLI_PATH, args, stdin), run(IRONCLI, args, stdin))


def on_nodes(name, args, stdin="", nodes=None):
    """The same arguments to both clients against each node (its datadir)"""
    for node in nodes or (C, I):
        both(f"{name} on {node.name}", [f"-datadir={node.dir}"] + args(node) if callable(args)
             else [f"-datadir={node.dir}"] + args, stdin)


DICLI_PATH = DIVICLI


# --- the nodes -----------------------------------------------------------------------

C = Node("divid", DIVID, 0, ["listen=1"])
if not C.wait_ready():
    print(f"FAIL   start: divid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
phrase = C.rpc("dumphdinfo")["mnemonic"]
I = Node("irondivid", IRONDIVID, 1, ["listen=0", f"connect=127.0.0.1:{PORT_BASE}"],
         env={"WALLET_MNEMONIC": phrase})
del phrase
if not I.wait_ready():
    print(f"FAIL   start: irondivid did not answer within {START_TIMEOUT} s", flush=True)
    sys.exit(1)
C.rpc("setgenerate", 25)
if not wait_for(lambda: I.rpc("getbestblockhash") == C.rpc("getbestblockhash"), 90):
    print("FAIL   setup: irondivid did not follow divid's chain", flush=True)
    sys.exit(1)
X = C.rpc("getnewaddress")
if not wait_for(lambda: I.rpc("validateaddress", X).get("ismine"), 30):
    print("FAIL   setup: irondivid's wallet does not hold divid's new address", flush=True)
    sys.exit(1)
LABELLED = C.rpc("getnewaddress")
if not wait_for(lambda: I.rpc("validateaddress", LABELLED).get("ismine"), 30):
    print("FAIL   setup: irondivid's wallet does not hold divid's second address", flush=True)
    sys.exit(1)
tip = C.rpc("getbestblockhash")
# One transaction in both mempools
pending = C.rpc("sendtoaddress", C.rpc("getnewaddress"), 1)
if not wait_for(lambda: pending in I.rpc("getrawmempool"), 60):
    print("FAIL   setup: irondivid did not get the mempool transaction", flush=True)
    sys.exit(1)
print(f"# divid {C.rpc('getinfo').get('version')}, irondivid {I.rpc('getnetworkinfo').get('version')}, "
      f"{C.rpc('getblockcount')} blocks", flush=True)

# Client directories: divi.conf with some settings left out, for the rows that give
# them on the command line
def client_dir(name, node, keep):
    d = os.path.join(WORK, f"client-{name}-{node.name}")
    os.makedirs(d, exist_ok=True)
    conf = {"regtest": "1", "rpcuser": node.user, "rpcpassword": PASSWORD, "rpcport": str(node.rpcport)}
    write_private(os.path.join(d, "divi.conf"), [f"{k}={v}" for k, v in conf.items() if k in keep])
    return d


def client_conf(name, lines):
    """A client directory whose divi.conf holds `lines`"""
    d = os.path.join(WORK, f"conf-{name}")
    os.makedirs(d, exist_ok=True)
    write_private(os.path.join(d, "divi.conf"), lines)
    return d


# --- the rows ------------------------------------------------------------------------

def rows():
    # results of each kind, and how each is printed
    on_nodes("getblockcount (a number)", ["getblockcount"])
    on_nodes("getbestblockhash (a string)", ["getbestblockhash"])
    on_nodes("getblock (an object)", ["getblock", tip])
    on_nodes("getblock false (a hex string)", ["getblock", tip, "false"])
    on_nodes("getrawmempool (one transaction)", ["getrawmempool"])
    on_nodes("getrawtransaction of it (a hex string)", ["getrawtransaction", pending])
    on_nodes("verifychain (a bool)", ["verifychain"])
    on_nodes("setaccount (null)", ["setaccount", X, "cli"])
    # how reals, nested objects, arrays and text are written
    on_nodes("getdifficulty (a real)", ["getdifficulty"])
    on_nodes("getbalance (an amount)", ["getbalance"])
    on_nodes("getblockchaininfo (nested, reals)", ["getblockchaininfo"])
    on_nodes("getmininginfo", ["getmininginfo"])
    on_nodes("getinfo", ["getinfo"])
    on_nodes("getnetworkinfo (arrays of objects)", ["getnetworkinfo"])
    on_nodes("gettxout of an output that is not there (null)", ["gettxout", tip, "9"])
    on_nodes("setaccount with non-ASCII text", ["setaccount", X, "Zürich ✓"])
    on_nodes("getaccount of non-ASCII text (a string reply)", ["getaccount", X])
    on_nodes("getaddressesbyaccount of non-ASCII text", ["getaddressesbyaccount", "Zürich ✓"])
    on_nodes("listaccounts (non-ASCII keys)", ["listaccounts"])
    on_nodes("setaccount with quotes and a backslash", ["setaccount", X, 'a "b" \\ c'])
    on_nodes("listaccounts (escaped keys)", ["listaccounts"])
    # a non-ASCII label divi-cli sets must read back as the text (divid's json_spirit
    # reads divi-cli's byte escapes back into the bytes)
    for node in (C, I):
        run(DIVICLI, [f"-datadir={node.dir}", "setaccount", LABELLED, "Zürich ✓"])
        compare(f"a non-ASCII label divi-cli set, read back by divi-cli on {node.name}",
                (0, "Zürich ✓\n", ""), run(DIVICLI, [f"-datadir={node.dir}", "getaccount", LABELLED]))
        compare(f"a non-ASCII label divi-cli set, read back by irondivi-cli on {node.name}",
                (0, "Zürich ✓\n", ""), run(IRONCLI, [f"-datadir={node.dir}", "getaccount", LABELLED]))
    # arguments: string, number, bool, JSON, text that is JSON, spaces
    on_nodes("getblockhash 1 (a number argument)", ["getblockhash", "1"])
    on_nodes("getblockhash \"1\" (a quoted number)", ["getblockhash", '"1"'])
    on_nodes("getblock <hash> 0 (a number for a bool)", ["getblock", tip, "0"])
    on_nodes("createrawtransaction [] {} (JSON arguments)", ["createrawtransaction", "[]", "{}"])
    on_nodes("createrawtransaction [ ] { } (JSON with spaces)", ["createrawtransaction", "[ ]", "{ }"])
    on_nodes("createrawtransaction with bad JSON", ["createrawtransaction", "[", "{}"])
    on_nodes("setaccount with an account of digits", ["setaccount", X, "1234"])
    on_nodes("setaccount with an account with spaces", ["setaccount", X, "a b"])
    on_nodes("getaccount after it", ["getaccount", X])
    on_nodes("validateaddress (an object of a string argument)", ["validateaddress", X])
    # errors
    on_nodes("getblockhash 9999 (an error)", ["getblockhash", "9999"])
    on_nodes("getblockhash (no argument: the help text)", ["getblockhash"])
    on_nodes("an unknown call", ["nosuchcall"])
    on_nodes("an unknown call with arguments", ["nosuchcall", "1", "x"])
    on_nodes("help", ["help"])
    on_nodes("help getblockcount", ["help", "getblockcount"])
    on_nodes("help of an unknown call", ["help", "nosuchcall"])
    # switches before the call, and options divi-cli does not have
    on_nodes("-stdin, nothing on stdin", ["-stdin", "getblockcount"])
    on_nodes("-stdin, the argument on stdin", ["-stdin", "getblockhash"], stdin="1\n")
    on_nodes("-named", ["-named", "getblockhash", "height=1"])
    on_nodes("an unknown switch", ["-nosuchswitch", "getblockcount"])
    on_nodes("only switches", ["-rpcwait=0"])
    # where the client finds the node and its credentials
    for node in (C, I):
        n = node.name
        both(f"-rpcport on the command line on {n}",
             [f"-datadir={client_dir('noport', node, {'regtest', 'rpcuser', 'rpcpassword'})}",
              f"-rpcport={node.rpcport}", "getblockcount"])
        both(f"-rpcconnect and -rpcport on the command line on {n}",
             [f"-datadir={client_dir('noport', node, {'regtest', 'rpcuser', 'rpcpassword'})}",
              "-rpcconnect=127.0.0.1", f"-rpcport={node.rpcport}", "getblockcount"])
        both(f"-rpcuser and -rpcpassword on the command line on {n}",
             [f"-datadir={client_dir('nocreds', node, {'regtest', 'rpcport'})}",
              f"-rpcuser={node.user}", f"-rpcpassword={PASSWORD}", "getblockcount"])
        both(f"-conf of another file on {n}",
             [f"-datadir={WORK}", f"-conf={os.path.join(client_dir('all', node, {'regtest', 'rpcuser', 'rpcpassword', 'rpcport'}), 'divi.conf')}",
              "getblockcount"])
        both(f"a wrong password on {n}", [f"-datadir={node.dir}", "-rpcpassword=wrong", "getblockcount"])
        both(f"a wrong user on {n}", [f"-datadir={node.dir}", "-rpcuser=nobody", "getblockcount"])
        both(f"no password set on {n}",
             [f"-datadir={client_dir('nopassword', node, {'regtest', 'rpcport'})}", "getblockcount"])
        both(f"-rpcport of a port nothing listens on, with {n}'s conf",
             [f"-datadir={node.dir}", "-rpcport=1", "getblockcount"])
    # Single-dash -name=value forms as divi-cli reads them (Settings.cpp:99-151):
    # the command line wins over divi.conf, --name is -name, -noname negates, the
    # last of two wins. Each against a divi.conf that holds a wrong value.
    for node in (C, I):
        n = node.name
        wrong_port = client_conf(f"wrongport-{n}", [f"regtest=1", f"rpcuser={node.user}",
                                                    f"rpcpassword={PASSWORD}", "rpcport=1"])
        wrong_creds = client_conf(f"wrongcreds-{n}", ["regtest=1", "rpcuser=nobody", "rpcpassword=wrong",
                                                      f"rpcport={node.rpcport}"])
        port = str(node.rpcport)
        for what, args in (
                ("-rpcport=<port> over divi.conf's rpcport", [f"-datadir={wrong_port}", f"-rpcport={port}"]),
                ("--rpcport=<port> over divi.conf's rpcport", [f"-datadir={wrong_port}", f"--rpcport={port}"]),
                ("-rpcport twice, the last wins", [f"-datadir={wrong_port}", f"-rpcport=1", f"-rpcport={port}"]),
                ("-rpcport <port> with a space", [f"-datadir={wrong_port}", "-rpcport", port]),
                ("--rpcport <port> with a space", [f"-datadir={wrong_port}", "--rpcport", port]),
                ("---rpcport=<port> (ignored)", [f"-datadir={wrong_port}", f"---rpcport={port}"]),
                ("-rpcconnect=127.0.0.1 -rpcport=<port>", [f"-datadir={wrong_port}", "-rpcconnect=127.0.0.1",
                                                          f"-rpcport={port}"]),
                ("-rpcconnect=localhost -rpcport=<port>", [f"-datadir={wrong_port}", "-rpcconnect=localhost",
                                                          f"-rpcport={port}"]),
                ("-rpcuser= -rpcpassword= over divi.conf's", [f"-datadir={wrong_creds}", f"-rpcuser={node.user}",
                                                             f"-rpcpassword={PASSWORD}"]),
                ("--datadir=<dir>", [f"--datadir={node.dir}"]),
                ("-conf=<name> relative to -datadir", [f"-datadir={os.path.dirname(wrong_port)}",
                                                      f"-conf={os.path.basename(wrong_port)}/divi.conf",
                                                      f"-rpcport={port}"]),
                ("-rpcwait=0", [f"-datadir={node.dir}", "-rpcwait=0"]),
                ("-norpcwait", [f"-datadir={node.dir}", "-norpcwait"]),
                ("-regtest=1 on the command line", [f"-datadir={client_conf(f'noregtest-{n}', [f'rpcuser={node.user}', f'rpcpassword={PASSWORD}', f'rpcport={port}'])}",
                                                    "-regtest=1"]),
                ("an option after the call", [f"-datadir={wrong_port}", "getblockcount", f"-rpcport={port}"])):
            call = [] if what == "an option after the call" else ["getblockcount"]
            both(f"{what} on {n}", args + call)

    # node-independent
    for what, args in (("-help", ["-help"]), ("-?", ["-?"]), ("-version", ["-version"]), ("no arguments", [])):
        core, iron = run(DIVICLI, args), run(IRONCLI, args)
        # exit code, stream and the first line's shape ("<name> RPC client version v<n>")
        shape = lambda out: (out[0], bool(out[1]), bool(out[2]),
                             re.sub(r"^.* RPC client version v\S+", "<name> RPC client version v<n>",
                                    out[1].split("\n", 1)[0]))
        row(f"{what}: exit code, stream and version line", json.dumps(shape(core)), json.dumps(shape(iron)),
            shape(core) == shape(iron))
        compare(f"{what}: text", core, iron)
    both("-datadir that does not exist", ["-datadir=/nonexistent/cli-replies", "getblockcount"])
    both("-conf that does not exist", [f"-datadir={WORK}", "-conf=/nonexistent/cli-replies/divi.conf", "getblockcount"])
    both("-regtest and -testnet together", ["-regtest", "-testnet", f"-datadir={C.dir}", "getblockcount"])


rows()

# divi-cli against irondivid, many times (the interop script sees it fail now and then)
height = str(C.rpc("getblockcount"))
bad = []
for k in range(REPEATS):
    out = run(DIVICLI, [f"-datadir={I.dir}", "getblockcount"])
    if out != (0, height + "\n", ""):
        bad.append((k, out))
row(f"divi-cli getblockcount on irondivid {REPEATS} times", f"{REPEATS} x exit 0, stdout {height}",
    f"{REPEATS - len(bad)} the same" + (f", first other: {bad[0]}" if bad else ""), not bad)

# The node down: both clients without -rpcwait, then with -rpcwait started before the node
for node in (C, I):
    node.stop()
for node in (C, I):
    both(f"the node down on {node.name}", [f"-datadir={node.dir}", "getblockcount"])
for node in (C, I):
    waiting = [subprocess.Popen([b, f"-datadir={node.dir}", "-rpcwait", "getblockcount"], cwd=WORK,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
               for b in (DIVICLI, IRONCLI)]
    time.sleep(2)
    node.start()
    outs = []
    for p in waiting:
        try:
            so, se = p.communicate(timeout=START_TIMEOUT)
            outs.append((p.returncode, so, se))
        except subprocess.TimeoutExpired:
            p.kill()
            outs.append(("timeout", "", ""))
    compare(f"-rpcwait started before the node on {node.name}", outs[0], outs[1])
    if not node.wait_ready():
        print(f"FAIL   restart: {node.name} did not answer within {START_TIMEOUT} s", flush=True)
        sys.exit(1)

for n in (C, I):
    n.stop()
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
