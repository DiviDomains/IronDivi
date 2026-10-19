#!/usr/bin/env python3
"""Fail-closed BIP39/Monero seed + raw-key masking filter for log output.

Reads text on stdin, writes it to stdout with every wallet seed phrase and raw
private key span replaced by a redaction marker. Unlike a keyword filter, it
detects secrets by *structure*: any checksum-valid 12/15/18/21/24-word BIP39 run
(or 25-word Monero run) is masked no matter what words surround it, so a bare
mnemonic line with no "seed"/"mnemonic"/"recovery" label is still caught.

WHY THIS EXISTS
---------------
The BasicSwap `prepare` path used to scrub its log with:

    grep -v -iE "mnemonic|seed|recovery"

That drops whole lines that happen to contain one of three keywords. It cannot
catch a bare 24-word mnemonic printed on its own line (no keyword), and it
destroys legitimate lines that merely mention the words. This filter replaces
it: it masks only the secret span, keyword or not, and passes everything else
through unchanged.

    python3 prepare.py --testnet ... 2>&1 | python3 mask_seed_log.py > prepare.log

WHAT IS MASKED
--------------
Using the vendored transcript-sweeper detector (see _vendor/, commit c2de727):
  * every AUTO_BLANK hit  - checksum-valid BIP39/Monero seed runs, xprv/yprv/
    zprv/tprv/uprv/vprv extended private keys, WIF keys, and 64-hex strings that
    sit next to a giveaway word (privkey/secret/seed/mnemonic/wif);
  * every seed-shaped REPORT_ONLY hit that carries a fingerprint - a
    checksum-valid seed window embedded inside a longer in-list run, and a
    valid-length run whose checksum fails (seed-shaped, worth masking in a log).

What is deliberately NOT masked, to keep logs usable:
  * bare 64-hex with no giveaway word (also matches txids / block hashes /
    sha256 digests that fill normal swap logs);
  * low-entropy in-list word runs of 4..11 words (ordinary prose that happens to
    use dictionary words) - these carry no fingerprint.

FAIL-CLOSED
-----------
  * If the detector or its word lists cannot be loaded at startup, the filter
    exits non-zero and copies NOTHING to stdout - it never degrades into a
    pass-through that would leak an unscrubbed stream.
  * If masking a single line raises, that line is replaced wholesale by a
    marker (never emitted raw) and the error is logged to stderr.

A SECRET VALUE NEVER LEAVES THIS PROCESS UNMASKED and is never written to
stderr: only offsets/markers are used.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
# Make the vendored, dependency-free detector importable even under `python -I`
# (which does not add the script directory to sys.path).
sys.path.insert(0, os.path.join(_HERE, "_vendor"))

try:
    import detector  # vendored transcript-sweeper detector (stdlib only)
    from detector import (
        MARKER_SEED,
        MARKER_KEY,
        TIER_AUTO_BLANK,
        BIP39_LENGTHS,
        MONERO_LENGTH,
        bip39_checksum_ok,
        monero_checksum_ok,
        normalize,
        detect,
        _runs,
        _tokenize,
    )
    # Touch the word lists at import time so a missing/corrupt list fails the
    # whole filter closed, before any stdin byte is processed.
    _BIP_INDEX = detector.bip39_words()[1]
    _MON_INDEX = detector.monero_words()[1]
except Exception as exc:  # fail closed: never pass the stream through unscrubbed
    sys.stderr.write(f"mask_seed_log: FATAL: detector unavailable ({type(exc).__name__}); refusing to run\n")
    raise SystemExit(2)

# Wholesale replacement for a line we could not analyze. Never the raw line.
_SAFE_LINE = "[REDACTED-LINE: seed-log-filter could not scrub this line]"

# (wordlist index, valid lengths, checksum fn) for each seed scheme.
_SEED_SCHEMES = (
    (_BIP_INDEX, BIP39_LENGTHS, bip39_checksum_ok),
    (_MON_INDEX, (MONERO_LENGTH,), monero_checksum_ok),
)


def _run_should_mask(words: list[str], valid_lengths, checksum_ok) -> bool:
    """True if this in-list word run holds (or IS) a seed, so the WHOLE run
    must be masked.

    Covers three cases, matching the detector's seed tiers but erring toward
    masking the entire enclosing run so no seed word ever survives next to an
    in-list neighbour (e.g. ``wallet seed <24 words>`` - 'wallet'/'seed' are
    BIP39 words and extend the run past an exact length):
      * an exact-length run whose own checksum passes (a bare mnemonic);
      * any checksum-valid window of a seed length embedded in a longer run;
      * a valid-length run whose checksum fails (seed-shaped near-miss / typo).
    Ordinary 4..11-word in-list prose, and longer runs with no validating
    window and no valid length, are NOT masked (kept readable).
    """
    n = len(words)
    if n in valid_lengths and checksum_ok(words):
        return True
    for wlen in valid_lengths:
        if n <= wlen:
            continue
        for i in range(0, n - wlen + 1):
            if checksum_ok(words[i:i + wlen]):
                return True
    return n in valid_lengths


def _seed_run_spans(norm: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    toks = _tokenize(norm)
    for index, valid_lengths, checksum_ok in _SEED_SCHEMES:
        for run in _runs(toks, index):
            if _run_should_mask([t.word for t in run], valid_lengths, checksum_ok):
                spans.append((run[0].start, run[-1].end, MARKER_SEED))
    return spans


def _key_spans(text: str) -> list[tuple[int, int, str]]:
    # Near-certain key material only: extended private keys, WIF, and 64-hex
    # next to a giveaway word. Bare 64-hex (txid/hash) is left intact.
    spans: list[tuple[int, int, str]] = []
    for h in detect(text):
        if h.kind in ("xprv", "wif") or (h.kind == "hex64" and h.tier == TIER_AUTO_BLANK):
            spans.append((h.start, h.end, MARKER_KEY))
    return spans


def mask_text(text: str) -> str:
    """Return `text` with every seed run and key span replaced by its marker.

    Seed hits are expanded to their whole enclosing in-list run, so a seed
    sitting next to an in-list neighbour word is fully masked (not just the
    detector's first sub-window). Spans are unioned and applied right-to-left;
    offsets index the normalized string, which is the same length as `text`
    (normalization is offset-preserving), so they map straight onto `text`.
    """
    norm = normalize(text)
    spans = _seed_run_spans(norm) + _key_spans(text)
    if not spans:
        return text
    spans.sort(key=lambda s: (s[0], s[1]))
    merged: list[list] = []
    for s, e, m in spans:
        if merged and s <= merged[-1][1]:                 # overlap/adjacency -> union
            merged[-1][1] = max(merged[-1][1], e)
            if m == MARKER_SEED:                           # seed marker takes precedence
                merged[-1][2] = MARKER_SEED
        else:
            merged.append([s, e, m])
    out = text
    for s, e, m in reversed(merged):
        out = out[:s] + m + out[e:]
    return out


def mask_line(line: str) -> str:
    """Mask one line (without its trailing newline). Fail-closed on error."""
    try:
        return mask_text(line)
    except Exception as exc:  # never emit the raw line if analysis failed
        sys.stderr.write(f"mask_seed_log: line scrub error ({type(exc).__name__}); line replaced\n")
        return _SAFE_LINE


def main(argv: list[str]) -> int:
    if any(a in ("-h", "--help") for a in argv):
        sys.stdout.write(__doc__ or "")
        return 0
    line_mode = any(a in ("-l", "--line") for a in argv)
    out = sys.stdout

    if line_mode:
        # Streaming: mask each line as it arrives (for a live `tail -f | ...`).
        # NB: a mnemonic split across lines (e.g. a numbered one-word-per-line
        # dump) is NOT caught in this mode - use the default whole-buffer mode.
        for raw in sys.stdin:
            if raw.endswith("\n"):
                body, nl = raw[:-1], "\n"
            else:
                body, nl = raw, ""
            out.write(mask_line(body))
            out.write(nl)
            out.flush()
        return 0

    # Default: read the whole input and mask across line boundaries, so a
    # mnemonic printed over several lines (the detector tolerates <=16 non-letter
    # chars, incl. newlines, between words) is still fully masked. Suits the
    # documented use of scrubbing a captured prepare log in one pass.
    data = sys.stdin.read()
    try:
        out.write(mask_text(data))
    except Exception as exc:  # fail closed: emit nothing raw
        sys.stderr.write(f"mask_seed_log: whole-buffer scrub error ({type(exc).__name__}); output suppressed\n")
        out.write(_SAFE_LINE + "\n")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
