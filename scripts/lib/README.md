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
