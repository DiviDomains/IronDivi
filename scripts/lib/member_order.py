"""The order of a reply's members and items next to divid's, for the scripts
that compare replies (opt-in: a script calls `difference` itself).

divid writes an object's members in the order its handler pushes them
(json_spirit's Object is a vector of pairs), and lists taken from a std::map or
std::set in the map's order. irondivid's serde_json keeps the order members are
inserted in (preserve_order), so its order is its handler's.

`difference(core, iron)` is None when both have the same order, else one line
naming where and both orders:
- an object: the members both have, in each node's order (members only one
  node has are left to the value comparison);
- a list holding the same items in another order (items compared as JSON
  text). A list with other items is left to the value comparison, and its
  items are checked one by one.

Call it with both replies as compared (after the script drops the fields it does
not compare), before any sorting the script does.
"""

import json

MAX = 160


def difference(core, iron, path="$"):
    if isinstance(core, dict) and isinstance(iron, dict):
        a = [k for k in core if k in iron]
        b = [k for k in iron if k in core]
        if a != b:
            return f"order of {path}: divid {names(a)}  irondivid {names(b)}"
        for k in a:
            d = difference(core[k], iron[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(core, (list, tuple)) and isinstance(iron, (list, tuple)):
        ta, tb = [text(x) for x in core], [text(x) for x in iron]
        if ta != tb and sorted(ta) == sorted(tb):
            n = next(i for i, (x, y) in enumerate(zip(ta, tb)) if x != y)
            return (f"order of {path}: the same {len(ta)} items, from [{n}] divid {items(core[n:])}"
                    f"  irondivid {items(iron[n:])}")
        for n, (x, y) in enumerate(zip(core, iron)):
            d = difference(x, y, f"{path}[{n}]")
            if d:
                return d
    return None


def text(v):
    return json.dumps(v, sort_keys=True)


def names(keys):
    s = ",".join(keys)
    return s if len(s) <= MAX else s[:MAX] + "..."


def items(v):
    s = ",".join(json.dumps(x)[:24] for x in v[:6]) + (",..." if len(v) > 6 else "")
    return "[" + s + "]"
