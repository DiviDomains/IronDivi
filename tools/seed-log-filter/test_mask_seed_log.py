#!/usr/bin/env python3
"""Unit tests for mask_seed_log.

Key test (the whole point of replacing the keyword grep): a BARE 24-word
checksum-valid BIP39 mnemonic - on its own line, with no "seed"/"mnemonic"/
"recovery" keyword anywhere - is masked.

Mnemonics are generated at runtime from entropy via the BIP39 checksum rule;
no seed phrase is ever written as a literal in this file. All-zero entropy is
used, which is a well-known PUBLIC test vector, not anyone's wallet.

Run:  python3 -I -m unittest -v     (from this directory)
  or: python3 -I test_mask_seed_log.py
"""

from __future__ import annotations

import hashlib
import os
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "_vendor"))

import detector  # noqa: E402  (vendored)
import mask_seed_log  # noqa: E402  (unit under test)

# The three keywords the old `grep -v -iE "mnemonic|seed|recovery"` filter keyed on.
OLD_KEYWORDS = ("mnemonic", "seed", "recovery")


def make_bip39(entropy: bytes) -> list[str]:
    """Build a checksum-valid BIP39 mnemonic from raw entropy (no literal words)."""
    wl, _ = detector.bip39_words()
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    cs = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    bits = (int.from_bytes(entropy, "big") << cs_bits) | cs
    n = (ent_bits + cs_bits) // 11
    return [wl[(bits >> ((n - 1 - i) * 11)) & 0x7FF] for i in range(n)]


def tokens(text: str) -> set[str]:
    return {t.strip(".,:;'\"").lower() for t in text.split()}


class BareMnemonicMasked(unittest.TestCase):
    def setUp(self) -> None:
        self.m24 = make_bip39(bytes(32))  # 24 words, all-zero entropy (public vector)
        self.m12 = make_bip39(bytes(16))  # 12 words
        # Preconditions: these really are checksum-valid seed phrases.
        self.assertEqual(len(self.m24), 24)
        self.assertEqual(len(self.m12), 12)
        self.assertTrue(detector.bip39_checksum_ok(self.m24))
        self.assertTrue(detector.bip39_checksum_ok(self.m12))

    def _assert_masked(self, words: list[str], line: str) -> None:
        out = mask_seed_log.mask_line(line)
        self.assertIn(detector.MARKER_SEED, out, f"marker missing: {out!r}")
        surviving = tokens(out) & set(words)
        self.assertEqual(surviving, set(), f"seed words survived masking: {sorted(surviving)}")

    def test_bare_24_word_line_is_masked(self) -> None:
        """THE requirement: a bare 24-word mnemonic, no keyword, is masked."""
        line = " ".join(self.m24)
        # The old keyword filter would have KEPT this line (it has no keyword).
        self.assertFalse(
            any(kw in line.lower() for kw in OLD_KEYWORDS),
            "test line unexpectedly contains an old-filter keyword",
        )
        self._assert_masked(self.m24, line)

    def test_bare_12_word_line_is_masked(self) -> None:
        self._assert_masked(self.m12, " ".join(self.m12))

    def test_mnemonic_embedded_in_a_log_line_is_masked(self) -> None:
        line = f"2026-01-01 12:00:00 INFO wallet restored from {' '.join(self.m24)} done"
        self._assert_masked(self.m24, line)
        # surrounding log text is preserved
        out = mask_seed_log.mask_line(line)
        self.assertIn("INFO wallet restored from", out)
        self.assertIn("done", out)

    def test_mnemonic_with_keyword_still_masked(self) -> None:
        # Masking must not DEPEND on the keyword, but must still work when present.
        self._assert_masked(self.m24, f"mnemonic: {' '.join(self.m24)}")

    def test_multiline_numbered_dump_masked_whole_buffer(self) -> None:
        # A mnemonic printed one numbered word per line defeats a strict line
        # filter; the default whole-buffer mask_text must still erase every word.
        dump = "\n".join(f"{i + 1}. {w}" for i, w in enumerate(self.m24))
        buf = f"RECOVERY PHRASE (write this down):\n{dump}\nDONE\n"
        out = mask_seed_log.mask_text(buf)
        self.assertIn(detector.MARKER_SEED, out)
        surviving = tokens(out) & set(self.m24)
        self.assertEqual(surviving, set(), f"seed words survived: {sorted(surviving)}")

    def test_in_list_neighbour_never_leaks_a_seed_word(self) -> None:
        # Regression: an in-list word (e.g. 'wallet'/'seed'/'legal') adjacent to
        # the seed extends the run past an exact length. The filter must mask the
        # WHOLE run, not just the detector's first sub-window. Exhaustive over
        # every BIP39 word, on both sides.
        wl, _ = detector.bip39_words()
        joined = " ".join(self.m24)
        seedset = set(self.m24)
        leaks = 0
        for x in wl:
            for line in (f"{x} {joined}", f"{joined} {x}"):
                out = mask_seed_log.mask_line(line)
                if tokens(out) & seedset:
                    leaks += 1
        self.assertEqual(leaks, 0, f"{leaks} neighbour lines leaked a seed word")


class NonSecretsPassThrough(unittest.TestCase):
    def test_ordinary_log_line_unchanged(self) -> None:
        line = "2026-01-01 INFO starting divid on testnet, rpcport=51473 peers=8"
        self.assertEqual(mask_seed_log.mask_line(line), line)

    def test_bare_txid_hex_unchanged(self) -> None:
        # A bare 64-hex (txid/block hash) with no giveaway word must survive, or
        # swap logs become useless. detect() flags it REPORT_ONLY; we don't mask.
        txid = "a" * 64
        line = f"INFO broadcast txid={txid} height=100"
        self.assertEqual(mask_seed_log.mask_line(line), line)

    def test_short_wordlist_prose_unchanged(self) -> None:
        # 4..11 in-list words that are ordinary prose must not be masked.
        line = "the quick brown fox jumps"
        self.assertEqual(mask_seed_log.mask_line(line), line)


class FailClosed(unittest.TestCase):
    def test_line_scrub_error_never_emits_raw(self) -> None:
        # If analysis raises, the raw line must NOT be emitted; a marker replaces it.
        secret_marker = "SENSITIVE-SHOULD-NOT-APPEAR"
        orig = mask_seed_log.mask_text

        def boom(_text: str) -> str:
            raise RuntimeError("synthetic failure")

        mask_seed_log.mask_text = boom
        try:
            out = mask_seed_log.mask_line(f"x {secret_marker} y")
        finally:
            mask_seed_log.mask_text = orig
        self.assertNotIn(secret_marker, out)
        self.assertEqual(out, mask_seed_log._SAFE_LINE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
