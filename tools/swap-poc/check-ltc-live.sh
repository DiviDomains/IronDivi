#!/usr/bin/env bash
# Litecoin live-readiness dry run (orchestrator, wave 3, 2026-10-11): proves the real
# litecoinspace.org testnet Esplora endpoint resolves and that LtcBackend builds, signs and
# consensus-verifies a claim and a refund HTLC spend against it — the exact production code
# path, nothing mocked, nothing broadcast. No funded key needed: a throwaway key is used
# unless SWAP_LTC_TEST_KEY_HEX is set (same env var the funded `live_fund_claim_refund` test
# reads), so once that key holds coins this same run also exercises (but never broadcasts)
# a real funding tx. See crates/swap-chain-ltc/examples/ltc_live_dry_run.rs.
source "$(dirname "$0")/lib.sh"

if rcargo run -q -p swap-chain-ltc --example ltc_live_dry_run; then
  pass "ltc live dry run: endpoints resolved, claim + refund signed and consensus-verified"
else
  fail "ltc live dry run failed"
fi
finish ltc-live
