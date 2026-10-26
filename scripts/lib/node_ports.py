"""Start a node again on new ports when another process took one of its own.

The scripts give each node ports from a fixed range; when another run (or anything else) already listens on one,
the daemon exits at once with "Unable to bind to <addr>:<port>" or "Address already in use". `popen` is
`subprocess.Popen` for a node: the process it returns looks the same, but when the node exits like that it is
started again, on two ports the system picked (at most BIND_RETRIES times), and `poll()` goes on saying it runs.
Any other exit, a bind failure on a port that is not the node's own, and a failure after the last retry are
reported as they are, with the last attempt's log, so the failure text is the one an unwrapped start gives.

Used like this in a script's `Node` (the arguments after `argv` are `subprocess.Popen`'s):

    self.proc = node_ports.popen(self, [self.binary, f"-datadir={self.dir}"], work=WORK, cwd=self.dir,
                                 stdout=o, stderr=e, start_new_session=True)

`node` has `p2p` and `rpcport` (the ports in its divi.conf, which the moved node's `port=` and `rpcport=` lines
are rewritten to) and may have `ports_moved()`, called after they changed for a node that keeps a copy of them.

A port a node was moved from is remembered in `moved`. Every start maps it in the node's divi.conf (`host:port`
words such as `connect=127.0.0.2:55500`) and in its arguments, so a node that names another node's port, whether
it starts after the move or is started again later, follows that node to the new one.
"""
import os
import re
import socket
import subprocess
import threading
import time

BIND_RETRIES = 5
BIND_MESSAGES = ("Address already in use", "Unable to bind")

PEER_WAIT = 90  # seconds a start waits for the node whose port it names to listen

moved = {}  # port a node was moved from -> the port it has now
_lock = threading.Lock()
_procs = []  # the nodes started by popen that were running when last looked at


def free_port(host):
    """A port nothing listens on now (the system picks it)"""
    with socket.socket() as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def now(port):
    """`port`, or the port its node has since been moved to"""
    with _lock:
        return moved.get(port, port)


def _word(port):
    return re.compile(r"(?<=:)%d\b" % port)


def follow(text):
    """`text` (a divi.conf, or one argument) with each host:port, `port=`, `rpcport=` and -port=, -rpcport=
    naming a port a node was moved from naming the new port"""
    with _lock:
        pairs = list(moved.items())
    for old, new in pairs:
        text = _word(old).sub(str(new), text)
        text = re.sub(r"(?m)^(-{0,2}(?:rpc)?port=)%d$" % old, r"\g<1>%d" % new, text)
    return text


def _read_from(path, offset):
    try:
        with open(path, errors="replace") as f:
            f.seek(offset)
            return f.read()
    except OSError:
        return ""


def _size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def _listening(pid, port):
    """True when process `pid` listens on TCP `port` (Linux /proc; an unreadable /proc says True: no way to know)"""
    inodes = set()
    for name in ("tcp", "tcp6"):
        try:
            with open("/proc/net/" + name) as f:
                next(f)
                for line in f:
                    cols = line.split()
                    if cols[3] == "0A" and int(cols[1].rsplit(":", 1)[1], 16) == port:
                        inodes.add(cols[9])
        except (OSError, StopIteration):
            return True
    if not inodes:
        return False
    try:
        for fd in os.listdir(f"/proc/{pid}/fd"):
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if link.startswith("socket:[") and link[8:-1] in inodes:
                return True
    except OSError:
        return False  # it has ended; poll() says how
    return False


def _own_conf_host(conf):
    for line in conf.splitlines():
        if line.startswith("bind="):
            return line[5:].split(":")[0] or "127.0.0.1"
    return "127.0.0.1"


def bind_failure(node, text):
    """True when a line of `text` (a node's log) is a bind failure naming the node's own P2P or RPC port, or no port"""
    ours = {str(node.p2p), str(node.rpcport)}
    for line in text.splitlines():
        if not any(m in line for m in BIND_MESSAGES):
            continue
        # "Unable to bind to 127.0.0.2:55500", "the RPC address 127.0.0.2 port 55501"; irondivid's RPC error names none
        ports = re.findall(r"(?:\d\.\d+\.\d+\.\d+|\]):(\d+)\b|\bport (\d+)\b", line)
        ports = [a or b for a, b in ports]
        if not ports or ours & set(ports):
            return True
    return False


def move_ports(node, datadir):
    """Give `node` two ports nothing listens on: its attributes, the `port=` and `rpcport=` lines of its divi.conf
    and `moved` (which the nodes naming the old ones follow). Returns the old (p2p, rpcport), or None when the
    node has no divi.conf to change"""
    conf_path = os.path.join(datadir, "divi.conf")
    try:
        with open(conf_path) as f:
            conf = f.read()
    except OSError:
        return None
    host = _own_conf_host(conf)
    old = (node.p2p, node.rpcport)
    new = (free_port(host), free_port(host))
    while new[1] == new[0]:
        new = (new[0], free_port(host))
    with _lock:
        moved[old[0]], moved[old[1]] = new
    node.p2p, node.rpcport = new
    _write_conf(conf_path, follow(conf))
    if hasattr(node, "ports_moved"):
        node.ports_moved()
    print(f"# {getattr(node, 'name', datadir)}: ports {old[0]}/{old[1]} in use, starting again on "
          f"{new[0]}/{new[1]}", flush=True)
    return old


def _write_conf(path, text):
    fd = os.open(path + ".new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.replace(path + ".new", path)


class Proc:
    """A `subprocess.Popen` of a node that is started again if its ports were taken"""

    def __init__(self, node, argv, work=None, datadir=None, **kw):
        self._node, self._work, self._kw = node, work, kw
        self._argv = list(argv)
        self._left = BIND_RETRIES
        self._datadir = datadir or next((a.split("=", 1)[1] for a in self._argv if a.startswith("-datadir=")), None)
        self._proc = None
        self._settled = False  # it listens on its P2P port, or it ended
        # a node made again for a later row has the ports of the first, which its conf maps to the new ones
        node.p2p, node.rpcport = now(node.p2p), now(node.rpcport)
        self._ports0 = (node.p2p, node.rpcport)
        self._wait_for_peers()
        self._launch()
        with _lock:
            _procs.append(self)

    def __getattr__(self, name):
        return getattr(self._proc, name)

    # -- the files whose new lines say why the node ended -----------------------------------------------------

    def _logs(self):
        paths = []
        for key in ("stdout", "stderr"):
            f = self._kw.get(key)
            if f is not None and hasattr(f, "name") and isinstance(f.name, str):
                paths.append(f.name)
        if self._datadir:
            paths += [os.path.join(self._datadir, "regtest", "debug.log"), os.path.join(self._datadir, "debug.log")]
        return list(dict.fromkeys(paths))

    def _named_ports(self):
        """The ports this node's divi.conf and arguments name as host:port"""
        text = " ".join(self._argv)
        if self._datadir:
            try:
                with open(os.path.join(self._datadir, "divi.conf")) as f:
                    text += "\n" + f.read()
            except OSError:
                pass
        return {int(p) for p in re.findall(r"(?<=:)(\d+)\b", text)}

    def _wait_for_peers(self):
        """A node naming the P2P port of a node that was started a moment ago waits until that node listens, so
        that a move of that node to new ports (found when it exits) is known when this one reads its conf"""
        named = self._named_ports()
        with _lock:
            others = [p for p in _procs if p is not self and not p._settled]
        for other in others:
            if not named & {other._ports0[0], other._node.p2p}:
                continue
            end = time.time() + PEER_WAIT
            while time.time() < end and not other._settle():
                time.sleep(0.1)

    def _settle(self):
        """True once the node listens on its P2P port or has ended (a node that ended for a bind failure is
        started again by poll(), and looked at again)"""
        if self._settled:
            return True
        code = self.poll()
        if code is not None or _listening(self._proc.pid, self._node.p2p):
            self._settled = True
        return self._settled

    def _follow_ports(self):
        """Map the ports other nodes were moved from in this node's arguments and divi.conf"""
        self._argv = [follow(a) for a in self._argv]
        if not self._datadir:
            return
        path = os.path.join(self._datadir, "divi.conf")
        try:
            with open(path) as f:
                old = f.read()
        except OSError:
            return
        new = follow(old)
        if new != old:
            _write_conf(path, new)

    def _launch(self):
        self._follow_ports()
        kw, reopened = dict(self._kw), []
        for key in ("stdout", "stderr"):
            f = kw.get(key)
            if f is not None and getattr(f, "closed", False):
                # the caller closed it after the first start: open the same file again, empty
                kw[key] = open(f.name, "w")
                reopened.append(kw[key])
        self._offsets = {p: _size(p) for p in self._logs()}
        try:
            self._proc = subprocess.Popen(self._argv, **kw)
        finally:
            for f in reopened:
                f.close()

    def _ended(self):
        return "\n".join(_read_from(p, self._offsets.get(p, 0)) for p in self._logs())

    # -- the retry ----------------------------------------------------------------------------------------------

    def _again(self):
        """Start the node again on new ports if it ended because one was taken; True when it was"""
        if not self._left or not self._datadir:
            return False
        if not bind_failure(self._node, self._ended()):
            self._left = 0  # it ended for another reason; later polls need not read its log again
            return False
        self._left -= 1
        old = move_ports(self._node, self._datadir)
        if old is None:
            return False
        self._launch()
        if self._work:
            with open(os.path.join(self._work, "pids"), "a") as f:
                f.write(f"{self._proc.pid}\n")
        return True

    def poll(self):
        while True:
            code = self._proc.poll()
            if code is None or not self._again():
                return code

    def wait(self, timeout=None):
        end = None if timeout is None else time.time() + timeout
        while True:
            left = None if end is None else max(0.0, end - time.time())
            code = self._proc.wait(left)
            if not self._again():
                return code


def popen(node, argv, work=None, datadir=None, **kw):
    """`subprocess.Popen(argv, **kw)` for `node`'s daemon; `work` is the directory holding the `pids` file the
    script keeps (the pid of a node started again is added to it); `datadir` is the node's, when `argv` does
    not carry a -datadir= of its own"""
    return Proc(node, argv, work=work, datadir=datadir, **kw)
