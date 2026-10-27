#!/usr/bin/env python3
"""Start-up wallet copies of Divi Core divid and irondivid, around encryptwallet.

Each node runs two sequences on regtest, side by side: (1) start, encryptwallet,
restart; (2) start, restart, encryptwallet, restart. After every start and step it
compares what each node prints on its console, what it logs about its backups, how
many copies sit in backups/ and monthlyBackups/, the encryptwallet reply, and at the
end how many copies still hold the recovery phrase in plain text. Each row prints
PASS (same as divid), KNOWN (a difference listed in README.md) or FAIL. Exit code =
FAILs.

Started by run.sh, which owns the work directory and stops the nodes. The phrase
and the passphrase live only in memory; they are never printed, written to a file
or put on a command line.
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

IRONDIVID, DIVID, PORT_BASE, WORK = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
# For the proof that a difference is caught: irondivid's value of the named row is
# changed before it is compared
INJECT = os.environ.get("WALLET_COPIES_INJECT", "")
RPC_TIMEOUT = 60
START_TIMEOUT = 120

# Differences irondivid has on purpose, one per row name ending. Each is listed in
# README.md with divid's source line; a KNOWN row that starts to match divid is a
# FAIL, so the list stays true.
KNOWN = {
    "copy names":
        "the wallet is a folder named wallet, so a copy is the folder wallet.<time>; divid's is the file "
        "wallet.dat.<time> (WalletBackupCreator.cpp:61-67)",
}

fails = 0


def row(name, core, iron):
    global fails
    if INJECT and name == INJECT:
        iron = ["injected"] + (iron if isinstance(iron, list) else [iron])
    same = core == iron
    reason = next((r for k, r in KNOWN.items() if name.endswith(": " + k)), None)
    if reason:
        word = "KNOWN" if not same else "FAIL"
        note = "  [known: " + reason + "]" if not same else "  [listed as KNOWN but now matches divid: update README.md]"
    else:
        word = "PASS" if same else "FAIL"
        note = ""
    if word == "FAIL":
        fails += 1
    print(f"{word:<5}  {name}  divid={json.dumps(core)}  irondivid={json.dumps(iron)}{note}"[:600], flush=True)


class Node:
    def __init__(self, name, binary, port):
        self.name, self.binary = name, binary
        self.dir = os.path.join(WORK, name)
        self.p2p, self.rpcport = port, port + 1
        password = secrets.token_hex(16)
        self.auth = base64.b64encode(f"copies:{password}".encode()).decode()
        os.makedirs(self.dir, mode=0o700)
        lines = [
            "regtest=1", f"port={self.p2p}", f"rpcport={self.rpcport}", "rpcuser=copies", f"rpcpassword={password}",
            "daemon=0", "printtoconsole=0", "server=1", "listen=0", "discover=0", "listenonion=0", "dnsseed=0",
            "bind=127.0.0.2", "rpcbind=127.0.0.2", "rpcallowip=127.0.0.0/8", "staking=0",
        ]
        fd = os.open(os.path.join(self.dir, "divi.conf"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write("\n".join(lines) + "\n")
        self.out_path = os.path.join(WORK, name + ".out")
        self.proc = None

    def start(self):
        """Start the node; the console text and log offset it starts from"""
        self.out_mark = os.path.getsize(self.out_path) if os.path.exists(self.out_path) else 0
        log = self.debug_log()
        self.log_mark = os.path.getsize(log) if log else 0
        out = open(self.out_path, "a")
        self.proc = subprocess.Popen([self.binary, f"-datadir={self.dir}"], cwd=self.dir,
                                     stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
        out.close()
        with open(os.path.join(WORK, "pids"), "a") as f:
            f.write(f"{self.proc.pid}\n")

    def call(self, method, *params):
        """('ok', result) or ('err', code, message)"""
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        req = urllib.request.Request(f"http://127.0.0.2:{self.rpcport}/", data=body,
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

    def debug_log(self):
        for sub in ("regtest", ""):
            p = os.path.join(self.dir, sub, "debug.log")
            if os.path.exists(p):
                return p
        return None

    def net_dir(self):
        """Where the wallet and its backup folders are: divid's regtest/, irondivid's data directory"""
        sub = os.path.join(self.dir, "regtest")
        return sub if os.path.isdir(sub) else self.dir

    # --- what is compared ---

    def console(self):
        """The console's warning and error lines since the last start"""
        with open(self.out_path, errors="replace") as f:
            f.seek(self.out_mark)
            text = f.read()
        return [l.strip() for l in text.splitlines() if re.match(r"\s*(Warning|Error|EXCEPTION)", l)]

    def backup_log(self):
        """The backup lines logged since the last start, paths named by their role"""
        log = self.debug_log()
        if not log:
            return []
        with open(log, errors="replace") as f:
            f.seek(self.log_mark)
            text = f.read()
        out = []
        for line in text.splitlines():
            m = re.search(r"(backing up wallet|Wallet file not found at .*|Creating backup of .*|Failed to create backup.*)$", line)
            if not m:
                continue
            t = m.group(1)
            t = re.sub(r"^Wallet file not found at .*\. Skipping backup\.\.\.$", "Wallet file not found at <wallet>. Skipping backup...", t)
            m2 = re.match(r"Creating backup of .* -> .*/(backups|monthlyBackups)/[^/]+$", t)
            if m2:
                t = f"Creating backup of <wallet> -> {m2.group(1)}/<copy>"
            out.append(t)
        return out

    def encrypt_log(self):
        """The encryption line logged since the last start, its iteration count left out"""
        log = self.debug_log()
        with open(log, errors="replace") as f:
            f.seek(self.log_mark)
            text = f.read()
        return sorted({re.sub(r"\d+$", "<n>", m) for m in re.findall(r"Encrypting Wallet with an nDeriveIterations of \d+", text)})

    def copies(self):
        """The copies in backups/ and monthlyBackups/ (names), absent folders as None"""
        out = {}
        for sub in ("backups", "monthlyBackups"):
            d = os.path.join(self.net_dir(), sub)
            out[sub] = sorted(os.listdir(d)) if os.path.isdir(d) else None
        return out

    def plain_copies(self, phrase):
        """How many copies in each folder still hold the phrase in plain text"""
        out = {}
        for sub, names in self.copies().items():
            n = 0
            for name in names or []:
                p = os.path.join(self.net_dir(), sub, name)
                files = [os.path.join(r, x) for r, _, xs in os.walk(p) for x in xs] if os.path.isdir(p) else [p]
                if any(phrase in open(x, "rb").read() for x in files):
                    n += 1
            out[sub] = n
        return out


def counts(c):
    return {k: (None if v is None else len(v)) for k, v in c.items()}


def name_form(c):
    """The copy names with their time replaced"""
    return {k: (None if v is None else sorted({re.sub(r"\.\d{4}-\d\d-\d\d-\d\d-\d\d$", ".<time>", n) for n in v})) for k, v in c.items()}


def clear_of_minute_end():
    """Both nodes start in the same minute: copies are named by the minute"""
    while time.time() % 60 > 50:
        time.sleep(1)


def start_both(nodes, seq, n):
    clear_of_minute_end()
    for node in nodes:
        node.start()
    for node in nodes:
        if not node.wait_ready():
            print(f"FAIL   {seq} start {n}: {node.name} did not start", flush=True)
            sys.exit(255)
    d, i = nodes
    row(f"{seq} start {n}: console warnings", d.console(), i.console())
    row(f"{seq} start {n}: backup log", d.backup_log(), i.backup_log())
    row(f"{seq} start {n}: copies", counts(d.copies()), counts(i.copies()))


def stop_both(nodes):
    for node in nodes:
        node.stop()


def encrypt_both(nodes, seq, passphrase):
    d, i = nodes
    replies = [node.call("encryptwallet", passphrase) for node in nodes]
    time.sleep(2)
    row(f"{seq} encryptwallet: reply", list(replies[0]), list(replies[1]))
    row(f"{seq} encryptwallet: node still running", d.proc.poll() is None, i.proc.poll() is None)
    row(f"{seq} encryptwallet: log", d.encrypt_log(), i.encrypt_log())
    row(f"{seq} encryptwallet: copies", counts(d.copies()), counts(i.copies()))


def sequence(seq, steps, port):
    nodes = [Node(f"{seq}-divid", DIVID, port), Node(f"{seq}-irondivid", IRONDIVID, port + 2)]
    passphrase = secrets.token_hex(16)
    phrases = {}
    n = 0
    for step in steps:
        if step == "start":
            n += 1
            start_both(nodes, seq, n)
            for node in nodes:
                if node.name not in phrases:
                    phrases[node.name] = node.call("dumphdinfo")[1]["mnemonic"].encode()
        elif step == "stop":
            stop_both(nodes)
        elif step == "encrypt":
            encrypt_both(nodes, seq, passphrase)
    stop_both(nodes)
    d, i = nodes
    row(f"{seq} end: copies holding the phrase in plain text",
        d.plain_copies(phrases[d.name]), i.plain_copies(phrases[i.name]))
    row(f"{seq} end: copy names", name_form(d.copies()), name_form(i.copies()))


sequence("seq1", ["start", "encrypt", "stop", "start"], PORT_BASE)
sequence("seq2", ["start", "stop", "start", "encrypt", "stop", "start"], PORT_BASE + 4)
print(f"FAILS {fails}", flush=True)
sys.exit(min(fails, 254))
