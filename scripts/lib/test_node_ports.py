"""Tests of node_ports against a daemon that is a few lines of Python. Run: python3 -I test_node_ports.py"""
import os
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import node_ports  # noqa: E402

HOST = "127.0.0.2"

# a daemon: binds the conf's port= and then runs; MODE in its conf picks how a bind failure looks
FAKE = r'''
import os, socket, sys, time
datadir = [a.split("=", 1)[1] for a in sys.argv if a.startswith("-datadir=")][0]
conf = dict(l.split("=", 1) for l in open(os.path.join(datadir, "divi.conf")).read().split() if "=" in l)
if conf.get("fail") == "always":
    print("Error: Unable to bind to %s:%s on this computer." % (conf["bind"], conf["port"]), file=sys.stderr)
    sys.exit(1)
if conf.get("fail") == "other":
    print("Error: Unable to bind to %s:%s on this computer." % (conf["bind"], int(conf["port"]) + 100), file=sys.stderr)
    sys.exit(1)
if conf.get("fail") == "option":
    print("Error: unknown option", file=sys.stderr)
    sys.exit(1)
if conf.get("rpc") == "partial":
    # divid with no -rpcbind: the IPv4 RPC port taken, it logs it and runs on
    r = socket.socket()
    try:
        r.bind((conf["bind"], int(conf["rpcport"])))
        r.listen()
    except OSError:
        print("ERROR: Binding RPC on address %s port %s failed: bind: Address already in use"
              % (conf["bind"], conf["rpcport"]), flush=True)
s = socket.socket()
try:
    s.bind((conf["bind"], int(conf["port"])))
except OSError:
    print("Error: Unable to bind to %s:%s on this computer." % (conf["bind"], conf["port"]), file=sys.stderr)
    sys.exit(1)
s.listen()
open(os.path.join(datadir, "up"), "w").write(conf["port"])
time.sleep(600)
'''


class Fake:
    def __init__(self, work, name, port, extra=()):
        self.name, self.p2p, self.rpcport = name, port, port + 1
        self.dir = os.path.join(work, name)
        os.makedirs(self.dir)
        self.conf = os.path.join(self.dir, "divi.conf")
        with open(self.conf, "w") as f:
            f.write("\n".join([f"port={port}", f"rpcport={port + 1}", f"bind={HOST}"] + list(extra)) + "\n")
        self.script = os.path.join(work, "fake.py")
        with open(self.script, "w") as f:
            f.write(FAKE)

    def start(self, work):
        self.err = open(os.path.join(work, self.name + ".err"), "w")
        proc = node_ports.popen(self, [sys.executable, "-I", self.script, f"-datadir={self.dir}"], work=work,
                                stdout=self.err, stderr=self.err)
        self.err.close()
        return proc

    def conf_text(self):
        with open(self.conf) as f:
            return f.read()


def wait(proc, secs=20):
    end = time.time() + secs
    while time.time() < end:
        code = proc.poll()
        if code is not None:
            return code
        time.sleep(0.05)
    return None


class NodePorts(unittest.TestCase):
    def setUp(self):
        node_ports.moved.clear()
        self.tmp = tempfile.TemporaryDirectory()
        self.work = self.tmp.name
        self.holders, self.procs = [], []

    def tearDown(self):
        for p in self.procs:
            p.kill()
        for h in self.holders:
            h.close()
        self.tmp.cleanup()

    def hold(self):
        s = socket.socket()
        s.bind((HOST, 0))
        s.listen()
        self.holders.append(s)
        return s.getsockname()[1]

    def up(self, node, proc):
        end = time.time() + 20
        while time.time() < end:
            proc.poll()
            if os.path.exists(os.path.join(node.dir, "up")):
                return True
            time.sleep(0.05)
        return False

    def test_a_taken_port_starts_the_node_on_new_ones_and_its_peers_follow(self):
        taken = self.hold()
        a = Fake(self.work, "a", taken)
        proc = a.start(self.work)
        self.procs.append(proc)
        self.assertTrue(self.up(a, proc))
        self.assertIsNone(proc.poll())
        self.assertNotEqual(a.p2p, taken)
        self.assertIn(f"port={a.p2p}\n", a.conf_text())
        self.assertIn(f"rpcport={a.rpcport}\n", a.conf_text())
        b = Fake(self.work, "b", self.hold(), [f"connect={HOST}:{taken}"])
        self.procs.append(b.start(self.work))
        self.assertIn(f"connect={HOST}:{a.p2p}\n", b.conf_text())
        self.assertEqual(node_ports.now(taken), a.p2p)
        with open(os.path.join(self.work, "pids")) as f:
            self.assertEqual(len(f.read().split()), 1)  # the pid of the second start

    def test_a_node_started_right_after_waits_for_the_node_whose_port_it_names(self):
        taken = self.hold()
        a = Fake(self.work, "a", taken)
        self.procs.append(a.start(self.work))  # nobody has looked at it yet
        b = Fake(self.work, "b", self.hold(), [f"connect={HOST}:{taken}"])
        self.procs.append(b.start(self.work))
        self.assertNotEqual(a.p2p, taken)
        self.assertIn(f"connect={HOST}:{a.p2p}\n", b.conf_text())
        self.assertTrue(os.path.exists(os.path.join(a.dir, "up")))

    def test_a_node_running_on_with_its_rpc_port_taken_is_started_again(self):
        held = self.hold()
        a = Fake(self.work, "a", node_ports.free_port(HOST), ["rpc=partial"])
        a.rpcport = held
        with open(a.conf, "a") as f:
            f.write(f"rpcport={held}\n")  # the later line is the one the fake reads
        proc = a.start(self.work)
        self.procs.append(proc)
        end = time.time() + 20
        while time.time() < end and a.rpcport == held:
            proc.poll()
            time.sleep(0.05)
        self.assertNotEqual(a.rpcport, held)
        self.assertIsNone(proc.poll())
        self.assertNotIn(f"rpcport={held}\n", a.conf_text())

    def test_a_node_that_ends_for_another_reason_is_not_started_again(self):
        a = Fake(self.work, "a", self.hold(), ["fail=option"])
        proc = a.start(self.work)
        self.assertEqual(wait(proc), 1)
        self.assertEqual(node_ports.moved, {})
        self.assertFalse(os.path.exists(os.path.join(self.work, "pids")))
        with open(os.path.join(self.work, "a.err")) as f:
            self.assertEqual(f.read(), "Error: unknown option\n")

    def test_a_bind_failure_on_a_port_that_is_not_the_nodes_is_not_started_again(self):
        port = self.hold()
        a = Fake(self.work, "a", port, ["fail=other"])
        self.assertEqual(wait(a.start(self.work)), 1)
        self.assertEqual(node_ports.moved, {})
        self.assertIn(f"port={port}\n", a.conf_text())

    def test_the_retries_end_and_the_last_failure_is_left_as_it_is(self):
        a = Fake(self.work, "a", self.hold(), ["fail=always"])
        self.assertEqual(wait(a.start(self.work)), 1)
        with open(os.path.join(self.work, "pids")) as f:
            self.assertEqual(len(f.read().split()), node_ports.BIND_RETRIES)
        with open(os.path.join(self.work, "a.err")) as f:
            text = f.read()
        self.assertEqual(text, f"Error: Unable to bind to {HOST}:{a.p2p} on this computer.\n")

    def test_the_bind_messages_of_both_daemons_name_the_nodes_port_or_none(self):
        class N:
            p2p, rpcport = 55520, 55521
        ours = [
            "Error: Unable to bind to 127.0.0.2:55520 on this computer. DIVI Core is probably already running.",
            "Error: Failed to start node: initialization error: Unable to bind to 127.0.0.2:55520 on this computer.",
            "Error: An error occurred while setting up the RPC address 127.0.0.2 port 55521 for listening: "
            "bind: Address already in use",
            "Error: RPC server error: IO error: Address already in use (os error 98)",
        ]
        others = [
            "Error: Unable to bind to 127.0.0.2:55590 on this computer.",  # a -whitebind the script chose
            "Error: An error occurred while setting up the RPC address 127.0.0.2 port 55599 for listening: "
            "bind: Address already in use",
            "Error: Cannot obtain a lock on data directory",
        ]
        for line in ours:
            self.assertTrue(node_ports.bind_failure(N, line), line)
        for line in others:
            self.assertFalse(node_ports.bind_failure(N, line), line)


if __name__ == "__main__":
    unittest.main()
