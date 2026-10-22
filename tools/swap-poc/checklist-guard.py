#!/usr/bin/env python3
"""checklist-guard.py <old-rev> [<new-rev>] — refuse a landing that silently drops or unticks a checklist row.

Compares every `- [ ]` / `- [x]` row in the tracked Markdown under docs/ between <old-rev> and <new-rev>
(default: the index, i.e. what land-private.sh is about to commit). A row counts as kept when, after its
code spans, file:line anchors and dated parentheticals are stripped, it matches a new row exactly, or —
the in-place rewrite case (a row ticked done, re-anchored, or extended) — a still-unmatched new row in the
same file carries the same bold label (`**Shared:**`, `**XMR:**`) and reads similarly enough. Anything
else is DROPPED; a `[x]` row whose match is `[ ]` is UNTICKED. Either prints the rows and exits 1.

Written after 97bc181 (2026-10-22) removed the finished "taker enforces its profile on maker terms" row
from mainnet-readiness.md while adding the DIVI row; c65b09c restored it. Standard library only.
"""
import difflib
import re
import subprocess
import sys

CHECK = re.compile(r"^\s*[-*] \[([ xX])\]\s*(.*)$")
LABEL = re.compile(r"^\*\*([^*]+)\*\*")


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True).stdout


def read(rev, path):
    return git("show", f":{path}" if rev is None else f"{rev}:{path}")


def rows(text):
    out = []
    for line in text.splitlines():
        m = CHECK.match(line)
        if m:
            out.append((m.group(1).lower() == "x", m.group(2)))
    return out


def key(t):
    t = re.sub(r"`[^`]*`", "", t)
    t = re.sub(r"\([^)]*\d{4}-\d\d-\d\d[^)]*\)", "", t)
    t = re.sub(r"[\w./-]+:\d+(-\d+)?", "", t)
    return re.sub(r"\W+", " ", t).lower().strip()


def label(t):
    m = LABEL.match(t)
    return m.group(1).strip().lower() if m else None


def ratio(a, b):
    return difflib.SequenceMatcher(None, a[:200], b[:200]).ratio()


def main():
    if len(sys.argv) not in (2, 3):
        print(__doc__.splitlines()[0], file=sys.stderr)
        return 2
    old = sys.argv[1]
    new = sys.argv[2] if len(sys.argv) == 3 else None
    paths = [p for p in git("ls-tree", "-r", "--name-only", old, "--", "docs").splitlines() if p.endswith(".md")]
    problems = []
    for path in paths:
        before = rows(read(old, path))
        if not before:
            continue
        after = rows(read(new, path))
        free = list(range(len(after)))
        pending = []
        for done, text in before:
            k = key(text)
            hit = next((i for i in free if key(after[i][1]) == k), None)
            if hit is None:
                pending.append((done, text))
                continue
            free.remove(hit)
            if done and not after[hit][0]:
                problems.append(f"UNTICKED {path}: [x] {text[:160]}")
        for done, text in pending:
            lab, k = label(text), key(text)
            cands = [i for i in free if label(after[i][1]) == lab and lab is not None]
            best = max(cands, key=lambda i: ratio(k, key(after[i][1])), default=None)
            if best is not None and ratio(k, key(after[best][1])) >= 0.3:
                free.remove(best)
                if done and not after[best][0]:
                    problems.append(f"UNTICKED {path}: [x] {text[:160]}")
                continue
            problems.append(f"DROPPED {path}: [{'x' if done else ' '}] {text[:160]}")
    for p in problems:
        print(p)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
