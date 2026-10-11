#!/usr/bin/env bash
# Zcash live-readiness dry run (lane zec, 2026-10-11): proves the real testnet.zec.rocks
# lightwalletd endpoint resolves and that ZecBackend builds, signs and consensus-verifies a
# claim and a refund HTLC spend against it — the exact production v6/ZIP-229 code path,
# nothing mocked, nothing broadcast. No funded key needed: a throwaway key is used unless
# SWAP_ZEC_TEST_KEY_HEX is set (same env var the funded `live_fund_claim_refund` test
# reads), so once that key holds coins this same run also exercises (but never broadcasts)
# a real funding tx. See crates/swap-chain-zec/examples/zec_live_dry_run.rs.
source "$(dirname "$0")/lib.sh"

if rcargo run -q -p swap-chain-zec --example zec_live_dry_run; then
  pass "zec live dry run: endpoints resolved, claim + refund signed and consensus-verified"
else
  fail "zec live dry run failed"
fi
finish zec-live
