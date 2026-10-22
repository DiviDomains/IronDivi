#!/usr/bin/env bash
# Lane usdc acceptance. See docs/plans/swap-poc/lanes/usdc.md.
source "$(dirname "$0")/lib.sh"
export PATH="$HOME/.foundry/bin:$PATH"
if [[ ! -f contracts/htlc/foundry.toml ]]; then fail "forge test in contracts/htlc"
else tool_check forge "forge test contracts/htlc" bash -c 'cd contracts/htlc && forge test'; fi
[[ -f contracts/htlc/src/Erc20Htlc.sol ]] && pass "Erc20Htlc.sol exists" || fail "contracts/htlc/src/Erc20Htlc.sol missing"
crate_green swap-chain-evm
no_todo crates/swap-chain-evm/src
require_tests swap-chain-evm \
  anvil_lock_claim anvil_lock_refund anvil_find_preimage_from_logs swap_id_matches_contract \
  live_sepolia_lock_claim
grep -q '^## Recommendation' docs/plans/swap-poc/usdc-design.md 2>/dev/null \
  && pass "usdc-design.md has a recommendation" || fail "docs/plans/swap-poc/usdc-design.md needs '## Recommendation'"
finish usdc
