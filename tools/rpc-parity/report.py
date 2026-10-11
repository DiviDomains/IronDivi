#!/usr/bin/env python3
"""Render parity.json (from rpc_parity.py) as a markdown matrix. Usage: report.py parity.json > out.md"""
import json
import sys
from collections import OrderedDict

d = json.load(open(sys.argv[1]))
by = OrderedDict()
for r in d["rows"]:
    by.setdefault(r["method"], []).append(r)


def classify(rows):
    """One verdict per method, worst row wins."""
    notes, worst = [], 0  # 0 match, 1 unverified, 2 value-diff, 3 shape/err-diff
    for r in rows:
        a = json.dumps(r["args"])[:60]
        if r["kind"] != "read":
            ce, re_ = r.get("cpp_err"), r.get("rust_err")
            if r["cpp_ok"] != r["rust_ok"]:
                worst = max(worst, 3)
                notes.append(f"{r['kind']} {a}: C++ {'ok' if r['cpp_ok'] else 'err ' + str(ce)} vs Rust {'ok' if r['rust_ok'] else 'err ' + str(re_)}")
            elif ce and re_ and ce[0] != re_[0]:
                worst = max(worst, 3)
                notes.append(f"{r['kind']} {a}: error code C++ {ce[0]} vs Rust {re_[0]}")
            continue
        if r["cpp_ok"] != r["rust_ok"]:
            worst = max(worst, 3)
            notes.append(f"args {a}: C++ {'ok' if r['cpp_ok'] else 'err ' + str(r.get('cpp_err'))} vs Rust {'ok' if r['rust_ok'] else 'err ' + str(r.get('rust_err'))}")
        elif not r["cpp_ok"]:
            if r["cpp_err"][0] != r["rust_err"][0]:
                worst = max(worst, 3)
                notes.append(f"args {a}: error code C++ {r['cpp_err'][0]} vs Rust {r['rust_err'][0]}")
        elif r["diffs"]:
            worst = max(worst, 3)
            notes.append(f"args {a}: " + "; ".join(r["diffs"][:6]))
        elif r.get("shape_unverified"):
            worst = max(worst, 1)
            notes.append(f"args {a}: a side returned empty — shape unverified")
    return worst, notes


LABEL = ["MATCH", "UNVERIFIED", "VALUE-DIFF", "DIFFERS"]
print("| Method | Verdict | Findings |\n|---|---|---|")
summary = [0, 0, 0, 0]
for m, rows in by.items():
    w, notes = classify(rows)
    summary[w] += 1
    print(f"| `{m}` | {LABEL[w]} | {'<br>'.join(n.replace('|', '/') for n in notes[:8])} |")
print("\nTotals: " + ", ".join(f"{LABEL[i]} {summary[i]}" for i in range(4)), file=sys.stderr)
