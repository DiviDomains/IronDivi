# seed-log-filter

A fail-closed stdin -> stdout filter that masks wallet seed phrases and raw
private keys in log output **by structure, not by keyword**.

## Why

The BasicSwap `prepare` path used to scrub its log like this:

```sh
python3 prepare.py --testnet ... 2>&1 | grep -v -iE "mnemonic|seed|recovery"
```

`grep -v` drops whole lines that contain one of those three words. It has two
failures:

1. **It misses a bare mnemonic.** A 24-word seed printed on its own line, with
   no "seed" / "mnemonic" / "recovery" label, sails straight through.
2. **It destroys good lines.** Any ordinary log line that merely mentions one of
   the words is deleted.

## What this does instead

```sh
python3 prepare.py --testnet ... 2>&1 | python3 tools/seed-log-filter/mask_seed_log.py > prepare.log
```

It detects secrets by shape and masks only the secret span:

- any **checksum-valid BIP39 run** of 12/15/18/21/24 words, or a **25-word
  Monero** run, regardless of surrounding words (so a bare mnemonic line is
  caught);
- **xprv/yprv/zprv/tprv/uprv/vprv** extended private keys and **WIF** keys
  (base58check-valid);
- **64-hex** strings sitting next to a giveaway word
  (`privkey`/`secret`/`seed`/`mnemonic`/`wif`);
- seed-shaped near-misses that still carry a fingerprint (a checksum-valid seed
  window embedded in a longer run; a valid-length run whose checksum fails).

It deliberately leaves **bare 64-hex** (txids, block hashes, sha256 digests) and
ordinary 4..11-word prose alone, so the log stays readable.

Masked spans become `[REDACTED-SEED]` / `[REDACTED-KEY]`. A seed found next to an
in-list neighbour word (`wallet`, `seed`, `legal` ... are all BIP39 words) is
masked across the **whole** in-list run, so no seed word survives beside it.

### Modes

- **Default (whole buffer):** reads all of stdin and masks across line
  boundaries, so a mnemonic printed over several lines (e.g. a numbered
  one-word-per-line dump) is still fully erased. Best for scrubbing a captured
  log in one pass (the documented use).
- **`--line` / `-l` (streaming):** masks each line as it arrives, for a live
  `tail -f | mask_seed_log.py`. A mnemonic split across lines is **not** caught
  in this mode.

## Fail-closed

- If the detector or its word lists can't load, the filter exits non-zero and
  writes **nothing** to stdout - it never degrades to a pass-through.
- If a single line can't be analyzed, that line is replaced wholesale by a
  marker; the raw line is never emitted.

No secret value ever leaves the process (not to stdout unmasked, not to stderr).

## Layout

```
mask_seed_log.py         the filter
test_mask_seed_log.py    unit tests (incl. "bare 24-word line is masked")
_vendor/detector.py      vendored transcript-sweeper detector, commit c2de727
_vendor/wordlists/       BIP39 + Monero English word lists
```

`_vendor/` is an unmodified copy of the transcript-sweeper detector (dependency
free, Python standard library only) at commit
`c2de7270816c1eacb31679676c414c2389bd7110`. To update, re-copy from upstream at
a known commit and bump the hash in `_vendor/detector.py`; do not hand-edit the
detection logic in the vendored copy.

## Test

```sh
cd tools/seed-log-filter
python3 -I -m unittest -v
```
