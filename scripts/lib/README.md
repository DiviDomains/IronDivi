# Shared code of the replies scripts

`member_order.py`: the order of a reply's members and list items next to divid's. divid writes an object's members
in the order its handler pushes them (json_spirit's `Object` is a vector of pairs) and a list taken from a
`std::map` or `std::set` in the map's order. irondivid's serde_json keeps the order its handler inserts members in
(`preserve_order`), so both orders can be compared.

`member_order.difference(divid's reply, irondivid's reply)` is `None` when both have the same order, else one line
naming the first object or list that differs and both orders:
- an object: the members both have, in each node's order (members only one node has are left to the value
  comparison);
- a list holding the same items in another order (items compared as JSON text). A list with other items is left to
  the value comparison, and its items are checked one by one.

It is opt-in: each `scripts/*-replies` check (and `mining-replies/compare.py`) calls it on the replies it compares,
after taking out the fields it does not compare and before any sorting of its own, and prints a row that differs
only in order as `ORDER`, a kind of FAIL counted in `FAILS`. `cli-replies` compares printed text, which has the
order in it. The checks run under `python3 -I` and add this directory to `sys.path` themselves.

`mnsync_stages.py`: the masternode sync stages of nodes over time. A `StagePoller` polls `mnsync status` on the
nodes side by side in a thread and keeps, per node, the stages it saw in order, each once; the scripts compare those
sequences with divid's, since each node's sync takes its steps at its own moments.

`node_ports.py`: a node whose port is taken starts again on new ones. The scripts give each node ports from their
`<port-base>` range, and another run holding one of them made the node exit at once with "Unable to bind to
<address>:<port>" or "Address already in use" and the script fail at setup. `node_ports.popen(node, argv, work=WORK,
...)` stands in for `subprocess.Popen` in a script's `Node`: when the process exits with one of those two messages
(in the output files it was given or the datadir's `debug.log`, new lines only) naming the node's own P2P or RPC port,
the node gets two ports the system picked (`node.p2p` and `node.rpcport` are set, the `port=` and `rpcport=` lines of
its `divi.conf` follow, a `ports_moved()` method of the node is called if it has one) and is started again, at most
`BIND_RETRIES` (5) times. Any other exit, a bind failure naming another port (a `-bind` or `-whitebind` the script
chose) and a failure after the last retry are what an unwrapped start gives, and the process's `poll()` and `wait()`
report them. A node that names the moved node's port (`connect=127.0.0.2:55500` in its `divi.conf` or arguments,
whether it is written before or after the move, and again when it is started later) is given the new one when it
starts. `node_ports.now(port)` is the port a port was moved to, for a script that keeps one in a variable.
The scripts print `# <node>: ports <old>/<old> in use, starting again on <new>/<new>` for each move.

`python3 -I test_node_ports.py` tests it with a daemon of a few lines of Python.
