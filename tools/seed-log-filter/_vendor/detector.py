# VENDORED, DO NOT EDIT HERE.
# Source: transcript-sweeper  sweeper/detector.py
# Commit: c2de7270816c1eacb31679676c414c2389bd7110  (tag: c2de727)
# This is an unmodified copy except for this provenance banner. It is
# dependency-free (Python standard library only). To update, re-copy from the
# upstream repo at a known commit and update the hash above; never hand-edit the
# detection logic in this vendored copy.
"""Secret detector for Claude Code transcripts.

Finds wallet seed phrases (BIP39 English, Monero English) and raw private keys
(extended private keys, WIF) in DECODED text, with a deliberate two-tier policy:

  * AUTO_BLANK  - near-certain secrets, safe to erase permanently:
        - an in-list word run of an exact seed length (BIP39 12/15/18/21/24,
          Monero 25) whose own checksum PASSES
        - an extended private key (xprv/yprv/zprv/tprv/uprv/vprv) with a valid
          base58check checksum
        - a WIF key (base58check-valid, version 0x80)
        - a bare 64-hex string WITH a giveaway word (privkey / private key /
          secret / seed / mnemonic / wif) within proximity in the same text
  * REPORT_ONLY - worth a human's eye but NOT safe to auto-erase:
        - in-list word runs of 4..11 words (below seed length)
        - valid-length runs whose checksum FAILS
        - a checksum-passing seed-length window embedded inside a longer run
          (e.g. a dump of the word list itself)
        - a bare 64-hex string with no adjacent giveaway word

xpub / ypub / zpub / tpub (public) keys are deliberately DROPPED.

Design notes:
  * A SECRET VALUE NEVER LEAVES THIS PROCESS. Hits carry only offsets, a tier,
    a reason, a marker and a one-way fingerprint - never the matched text.
  * All matching happens on the DECODED string value (one JSON level undone).
    Double-escaped JSON-in-JSON content still carries literal ``\\n`` / ``\\t``
    etc. between words, so those two-char escape literals are replaced with
    equal-length blanks before tokenizing (offset-preserving, so a rewrite can
    map a span straight back onto the decoded value).

This module is deliberately DEPENDENCY-FREE (standard library only): hashlib,
zlib, re, pathlib, hmac. See requirements.txt.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import zlib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# --------------------------------------------------------------------------- #
# Tiers, markers, reasons
# --------------------------------------------------------------------------- #

TIER_AUTO_BLANK = "AUTO_BLANK"
TIER_REPORT_ONLY = "REPORT_ONLY"

MARKER_SEED = "[REDACTED-SEED]"
MARKER_KEY = "[REDACTED-KEY]"

# Valid mnemonic lengths.
BIP39_LENGTHS = (12, 15, 18, 21, 24)
MONERO_LENGTH = 25

# Below this many consecutive in-list words we do not even flag a run.
MIN_RUN_WORDS = 4

# Largest run of consecutive non-letter characters still treated as a single
# word separator inside a run (newlines, "1. ", JSON punctuation ...). Beyond
# this, the run is considered broken.
MAX_WORD_GAP = 16

# Giveaway words that promote a bare 64-hex string to AUTO_BLANK when found
# within this many characters of the hex span.
GIVEAWAY_WORDS = ("privkey", "private key", "secret", "seed", "mnemonic", "wif")
GIVEAWAY_WINDOW = 100

# Private extended-key version bytes (serialized prefix). Public variants are
# intentionally absent so xpub/ypub/zpub/tpub are dropped.
XPRV_VERSIONS = {
    bytes.fromhex("0488ade4"): "xprv",  # mainnet BIP32
    bytes.fromhex("049d7878"): "yprv",  # BIP49
    bytes.fromhex("04b2430c"): "zprv",  # BIP84
    bytes.fromhex("04358394"): "tprv",  # testnet BIP32
    bytes.fromhex("044a4e28"): "uprv",  # testnet BIP49
    bytes.fromhex("045f18bc"): "vprv",  # testnet BIP84
}


# --------------------------------------------------------------------------- #
# Word lists
# --------------------------------------------------------------------------- #

_WORDLIST_DIR = Path(__file__).resolve().parent / "wordlists"


@lru_cache(maxsize=None)
def _load_wordlist(name: str) -> tuple[tuple[str, ...], dict]:
    path = _WORDLIST_DIR / name
    words = tuple(
        w.strip().lower()
        for w in path.read_text(encoding="utf-8").splitlines()
        if w.strip()
    )
    index = {w: i for i, w in enumerate(words)}
    return words, index


def bip39_words() -> tuple[tuple[str, ...], dict]:
    return _load_wordlist("bip39-english.txt")


def monero_words() -> tuple[tuple[str, ...], dict]:
    return _load_wordlist("monero-english.txt")


# --------------------------------------------------------------------------- #
# Hit record
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Hit:
    """A single detection. Carries NO secret material.

    start/end are offsets into the DECODED string value the detector was run
    on (suitable for a span rewrite). fingerprint is a one-way sha256 prefix of
    the normalized matched text, for de-duplication / vector matching only; it
    is omitted (empty) for low-entropy short word runs.
    """

    start: int
    end: int
    kind: str          # seed_bip39 | seed_monero | xprv | wif | hex64 | word_run
    tier: str          # AUTO_BLANK | REPORT_ONLY
    reason: str
    marker: str
    length: int        # characters in the matched span
    word_count: int    # number of words (0 for key/hex hits)
    fingerprint: str   # sha256 hex prefix, or "" for low-entropy runs


_FP_SALT = b"transcript-sweeper/v1/fingerprint"


def _fingerprint(text: str) -> str:
    """One-way, salted fingerprint. Not reversible; only equal inputs collide."""
    return hmac.new(_FP_SALT, text.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Escape normalization (offset-preserving)
# --------------------------------------------------------------------------- #

# Two-char backslash escape literals that appear in double-escaped
# JSON-in-JSON content after one json.loads. Each is replaced by two blanks so
# character offsets are preserved exactly.
_ESCAPE_RE = re.compile(r"\\[ntrbf\"\\/]")


def normalize(decoded: str) -> str:
    """Replace literal two-char escape sequences with equal-length blanks.

    The input is an already-JSON-decoded string. Real control characters
    (actual newlines/tabs) are left as-is; they are non-letters and so already
    act as separators. Only *literal* ``\\n`` style two-char runs (produced by
    double escaping) need flattening, and we do it offset-preserving.
    """
    return _ESCAPE_RE.sub("\x00\x00", decoded)


# --------------------------------------------------------------------------- #
# Checksums
# --------------------------------------------------------------------------- #


def bip39_checksum_ok(words: list[str]) -> bool:
    _, index = bip39_words()
    n = len(words)
    if n not in BIP39_LENGTHS:
        return False
    bits = 0
    for w in words:
        idx = index.get(w)
        if idx is None:
            return False
        bits = (bits << 11) | idx
    total = n * 11
    ent_bits = total * 32 // 33
    cs_bits = total - ent_bits          # 4,5,6,7,8 -> always within first byte
    ent = bits >> cs_bits
    cs = bits & ((1 << cs_bits) - 1)
    ent_bytes = ent.to_bytes(ent_bits // 8, "big")
    digest = hashlib.sha256(ent_bytes).digest()
    expected = digest[0] >> (8 - cs_bits)
    return cs == expected


def monero_checksum_ok(words: list[str], prefix_len: int = 3) -> bool:
    _, index = monero_words()
    if len(words) != MONERO_LENGTH:
        return False
    for w in words:
        if w not in index:
            return False
    first = words[:24]
    checksum_word = words[24]
    trimmed = "".join(w[:prefix_len] for w in first)
    idx = zlib.crc32(trimmed.encode("utf-8")) % len(first)
    return first[idx] == checksum_word


# --------------------------------------------------------------------------- #
# base58check (for WIF and extended private keys)
# --------------------------------------------------------------------------- #

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58decode(s: str) -> bytes | None:
    num = 0
    for ch in s:
        v = _B58_INDEX.get(ch)
        if v is None:
            return None
        num = num * 58 + v
    body = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + body


def _b58check_payload(s: str) -> bytes | None:
    raw = _b58decode(s)
    if raw is None or len(raw) < 5:
        return None
    payload, checksum = raw[:-4], raw[-4:]
    want = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if want != checksum:
        return None
    return payload


def wif_ok(s: str) -> bool:
    payload = _b58check_payload(s)
    if payload is None:
        return False
    # version(1)=0x80 + key(32) [+ 0x01 compressed flag]
    if not payload or payload[0] != 0x80:
        return False
    return len(payload) in (33, 34)


def xprv_kind(s: str) -> str | None:
    payload = _b58check_payload(s)
    if payload is None or len(payload) != 78:
        return None
    return XPRV_VERSIONS.get(payload[:4])


# --------------------------------------------------------------------------- #
# Tokenization
# --------------------------------------------------------------------------- #

_WORD_RE = re.compile(r"[A-Za-z]+")


@dataclass(frozen=True)
class _Tok:
    word: str   # lowercased
    start: int
    end: int


def _tokenize(norm: str) -> list[_Tok]:
    return [_Tok(m.group(0).lower(), m.start(), m.end()) for m in _WORD_RE.finditer(norm)]


def _runs(tokens: list[_Tok], index: dict) -> list[list[_Tok]]:
    """Maximal runs of consecutive in-list tokens separated by <= MAX_WORD_GAP
    non-letter characters."""
    runs: list[list[_Tok]] = []
    current: list[_Tok] = []
    for tok in tokens:
        in_list = tok.word in index
        if in_list and current and (tok.start - current[-1].end) <= MAX_WORD_GAP:
            current.append(tok)
        elif in_list:
            if len(current) >= MIN_RUN_WORDS:
                runs.append(current)
            current = [tok]
        else:
            if len(current) >= MIN_RUN_WORDS:
                runs.append(current)
            current = []
    if len(current) >= MIN_RUN_WORDS:
        runs.append(current)
    return runs


# --------------------------------------------------------------------------- #
# Seed detection
# --------------------------------------------------------------------------- #


def _seed_hits_for_list(
    norm: str,
    kind: str,
    index: dict,
    valid_lengths: tuple[int, ...],
    checksum_ok,
) -> list[Hit]:
    hits: list[Hit] = []
    for run in _runs(_tokenize(norm), index):
        words = [t.word for t in run]
        n = len(words)
        span_start, span_end = run[0].start, run[-1].end
        span_text = norm[span_start:span_end]

        if n in valid_lengths and checksum_ok(words):
            # Exact maximal run of a seed length that validates -> AUTO_BLANK.
            hits.append(
                Hit(
                    start=span_start,
                    end=span_end,
                    kind=kind,
                    tier=TIER_AUTO_BLANK,
                    reason=f"{n}-word {kind} run, checksum PASS",
                    marker=MARKER_SEED,
                    length=span_end - span_start,
                    word_count=n,
                    fingerprint=_fingerprint(span_text),
                )
            )
            continue

        # Not an exact validating run. Look for a validating window embedded in
        # a longer run (e.g. a word-list dump) -> REPORT_ONLY only.
        embedded = None
        for wlen in valid_lengths:
            if n <= wlen:
                continue
            for i in range(0, n - wlen + 1):
                window = words[i : i + wlen]
                if checksum_ok(window):
                    ws = run[i].start
                    we = run[i + wlen - 1].end
                    embedded = (wlen, ws, we)
                    break
            if embedded:
                break

        if embedded:
            wlen, ws, we = embedded
            hits.append(
                Hit(
                    start=ws,
                    end=we,
                    kind=kind,
                    tier=TIER_REPORT_ONLY,
                    reason=f"embedded {wlen}-word checksum-PASS inside {n}-word run",
                    marker=MARKER_SEED,
                    length=we - ws,
                    word_count=wlen,
                    fingerprint=_fingerprint(norm[ws:we]),
                )
            )
            continue

        if n in valid_lengths:
            hits.append(
                Hit(
                    start=span_start,
                    end=span_end,
                    kind=kind,
                    tier=TIER_REPORT_ONLY,
                    reason=f"{n}-word {kind} run, checksum FAIL",
                    marker=MARKER_SEED,
                    length=span_end - span_start,
                    word_count=n,
                    fingerprint=_fingerprint(span_text),
                )
            )
            continue

        # Plain in-list run: 4..11 (below seed length) or an odd length with no
        # validating window. Low entropy, not a secret -> no fingerprint.
        bucket = "below seed length" if n < min(valid_lengths) else "no checksum-passing seed"
        hits.append(
            Hit(
                start=span_start,
                end=span_end,
                kind="word_run",
                tier=TIER_REPORT_ONLY,
                reason=f"{n}-word {kind} in-list run ({bucket})",
                marker=MARKER_SEED,
                length=span_end - span_start,
                word_count=n,
                fingerprint="",
            )
        )
    return hits


def _seed_hits(norm: str) -> list[Hit]:
    _, bip_index = bip39_words()
    _, mon_index = monero_words()
    hits = _seed_hits_for_list(norm, "BIP39", bip_index, BIP39_LENGTHS, bip39_checksum_ok)
    hits += _seed_hits_for_list(norm, "Monero", mon_index, (MONERO_LENGTH,), monero_checksum_ok)
    return hits


# --------------------------------------------------------------------------- #
# Raw-key detection
# --------------------------------------------------------------------------- #

# base58 char class, with boundaries so we never match a fragment of a longer
# base58 string.
_B58 = "1-9A-HJ-NP-Za-km-z"
_XPRV_RE = re.compile(rf"(?<![{_B58}])(?:xprv|yprv|zprv|tprv|uprv|vprv)[{_B58}]{{100,120}}(?![{_B58}])")
_WIF_RE = re.compile(rf"(?<![{_B58}])[5KL][{_B58}]{{50,51}}(?![{_B58}])")
# 64 hex, not a fragment of a 128-hex (sha512/sig) or 66-hex (pubkey) string.
_HEX64_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")


def _key_hits(norm: str) -> list[Hit]:
    hits: list[Hit] = []
    lower = norm.lower()

    for m in _XPRV_RE.finditer(norm):
        s = m.group(0)
        kind = xprv_kind(s)
        if kind is None:
            continue
        hits.append(
            Hit(
                start=m.start(),
                end=m.end(),
                kind="xprv",
                tier=TIER_AUTO_BLANK,
                reason=f"extended private key ({kind}), base58check valid",
                marker=MARKER_KEY,
                length=len(s),
                word_count=0,
                fingerprint=_fingerprint(s),
            )
        )

    for m in _WIF_RE.finditer(norm):
        s = m.group(0)
        if not wif_ok(s):
            continue
        hits.append(
            Hit(
                start=m.start(),
                end=m.end(),
                kind="wif",
                tier=TIER_AUTO_BLANK,
                reason="WIF private key, base58check valid",
                marker=MARKER_KEY,
                length=len(s),
                word_count=0,
                fingerprint=_fingerprint(s),
            )
        )

    for m in _HEX64_RE.finditer(norm):
        s = m.group(0)
        lo = max(0, m.start() - GIVEAWAY_WINDOW)
        hi = min(len(norm), m.end() + GIVEAWAY_WINDOW)
        window = lower[lo : m.start()] + " " + lower[m.end() : hi]
        hit_word = None
        for gw in GIVEAWAY_WORDS:
            if gw in window:
                hit_word = gw
                break
        if hit_word:
            hits.append(
                Hit(
                    start=m.start(),
                    end=m.end(),
                    kind="hex64",
                    tier=TIER_AUTO_BLANK,
                    reason=f"64-hex with giveaway word {hit_word!r} within {GIVEAWAY_WINDOW} chars",
                    marker=MARKER_KEY,
                    length=64,
                    word_count=0,
                    fingerprint=_fingerprint(s),
                )
            )
        else:
            hits.append(
                Hit(
                    start=m.start(),
                    end=m.end(),
                    kind="hex64",
                    tier=TIER_REPORT_ONLY,
                    reason="bare 64-hex, no giveaway word (also matches txid/hash/sha256)",
                    marker=MARKER_KEY,
                    length=64,
                    word_count=0,
                    fingerprint=_fingerprint(s),
                )
            )
    return hits


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def detect(decoded: str) -> list[Hit]:
    """Return all hits in one already-JSON-decoded string value.

    Never returns secret material; only offsets/metadata. Hits are sorted by
    start offset.
    """
    if not decoded:
        return []
    norm = normalize(decoded)
    hits = _seed_hits(norm)
    hits += _key_hits(norm)
    hits.sort(key=lambda h: (h.start, h.end))
    return hits


def _clean_snippet(masked: str, lo: int, hi: int) -> str:
    snippet = masked[lo:hi]
    snippet = (
        snippet.replace("\x00", " ")
        .replace("\n", " ")
        .replace("\r", " ")
        .replace("\t", " ")
    )
    snippet = re.sub(r"\s+", " ", snippet).strip()
    prefix = "..." if lo > 0 else ""
    suffix = "..." if hi < len(masked) else ""
    return f"{prefix}{snippet}{suffix}"


def mask_all(decoded: str, hits: list[Hit], radius: int = 40) -> list[str]:
    """Return a masked context snippet for each hit, in the SAME order as hits.

    The whole value is masked ONCE (every detected span of both tiers blanked
    with its marker), so no secret - and no fragment of a neighbouring secret -
    can leak through any context, and the cost is O(len) rather than O(hits^2)
    for values with many hits (e.g. a tool output full of txids).
    """
    if not hits:
        return []
    norm = normalize(decoded)
    order = sorted(range(len(hits)), key=lambda i: (hits[i].start, hits[i].end))
    pieces: list[str] = []
    marker_pos: dict[int, tuple[int, int]] = {}
    pos = 0        # read position in norm
    mlen = 0       # length written to masked so far
    for i in order:
        h = hits[i]
        start = max(h.start, pos)   # clamp against any accidental overlap
        if start > pos:
            pieces.append(norm[pos:start])
            mlen += start - pos
        m_start = mlen
        pieces.append(h.marker)
        mlen += len(h.marker)
        marker_pos[i] = (m_start, mlen)
        pos = max(pos, h.end)
    pieces.append(norm[pos:])
    masked = "".join(pieces)

    contexts: list[str] = []
    for i in range(len(hits)):
        m_start, m_end = marker_pos[i]
        lo = max(0, m_start - radius)
        hi = min(len(masked), m_end + radius)
        contexts.append(_clean_snippet(masked, lo, hi))
    return contexts


def mask_context(decoded: str, hits: list[Hit], target: Hit, radius: int = 40) -> str:
    """Single-hit convenience wrapper around mask_all (used by tests)."""
    contexts = mask_all(decoded, hits, radius)
    for h, ctx in zip(hits, contexts):
        if h is target:
            return ctx
    return ""
