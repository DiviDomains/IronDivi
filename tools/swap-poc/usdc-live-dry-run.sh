#!/usr/bin/env bash
# Anvil-backed dry run of tools/swap-poc/usdc-live.sh: the same operations, against a
# throwaway local chain instead of real Sepolia, with throwaway keys instead of 1Password.
# No secrets, no real network writes, safe to run anywhere (including hp2).
#
#   tools/swap-poc/usdc-live-dry-run.sh
#
# Step by step, mirroring usdc-live.sh:
#   1. Spin up anvil; deploy a MockErc20 (stands in for real Sepolia USDC, which has no
#      code on a fresh local chain) and mint it to a throwaway "taker" key.
#   2. `sepolia_ops deploy` — the exact command usdc-live.sh runs to deploy `Erc20Htlc`
#      (including the `--network` flag usdc-live.sh now always passes).
#   3. `sepolia_ops send-eth` / `send-usdc` — the exact commands usdc-live.sh runs to fund
#      the maker from the taker.
#   4. The anvil-backed proof that `UsdcBackend` locks/claims/refunds for real:
#      `anvil_lock_claim`, `anvil_lock_refund`, `anvil_find_preimage_from_logs`,
#      `swap_id_matches_contract` (swap-chain-evm) — these are the anvil equivalent of
#      `live_sepolia_lock_claim`, which hardcodes the real Sepolia USDC address and so
#      cannot itself run against a local chain with nothing deployed at that address.
#   5. The anvil-backed proof that a real DIVI<->USDC swap completes end to end:
#      `usdc_swap_forward`/`usdc_swap_reverse` (divi-swap's tests/usdc.rs) — mock DIVI, a
#      real `UsdcBackend` over this same anvil. This validates the swap logic through the
#      engine directly, not through the divi-swapd/divi-swap CLI *binaries* wired together
#      over HTTP; doing that too would need the dry run to also drive anvil's block
#      production in lockstep with the daemon's confirmation polling from a second
#      process, which is exactly what tests/usdc.rs already does under full, non-racy
#      control inside one process. (Same scope boundary e2e.sh documents for its own
#      --backend mock: plumbing proven, cross-process swap proven separately.)
set -euo pipefail

die() { echo "usdc-live-dry-run: $*" >&2; exit 1; }

ROOT="$(git rev-parse --show-toplevel)"
export PATH="$HOME/.foundry/bin:/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"
cd "$ROOT"

command -v anvil >/dev/null || die "anvil not found on PATH (foundryup)"
command -v forge >/dev/null || die "forge not found on PATH (foundryup)"
command -v cast >/dev/null || die "cast not found on PATH (foundryup)"

echo "usdc-live-dry-run: building divi-swap's engine tests and sepolia_ops"
cargo build -q -p swap-chain-evm --features live --example sepolia_ops

anvil_log="$(mktemp -d)/anvil.log"
anvil --port 0 >"$anvil_log" 2>&1 &
anvil_pid=$!
cleanup() { kill "$anvil_pid" 2>/dev/null || true; wait "$anvil_pid" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

for _ in $(seq 1 50); do
  grep -q "Listening on" "$anvil_log" && break
  kill -0 "$anvil_pid" 2>/dev/null || die "anvil exited during startup: $(cat "$anvil_log")"
  sleep 0.2
done
port="$(sed -n 's/.*Listening on 127\.0\.0\.1:\([0-9]*\).*/\1/p' "$anvil_log" | head -1)"
[[ -n "$port" ]] || die "could not read anvil's port from $anvil_log"
rpc_url="http://127.0.0.1:$port"
echo "usdc-live-dry-run: anvil up at $rpc_url"

# Anvil's own well-known dev accounts (genesis-funded with 10000 ETH each) — not secrets,
# not reused anywhere real; this is exactly what crates/swap-chain-evm/src/tests.rs uses.
taker_key=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
taker_addr=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
maker_addr=0x70997970C51812dc3A010C7d01b50e0d17dc79C8

echo "usdc-live-dry-run: deploying a MockErc20 (stands in for Sepolia USDC) and minting it to the taker"
(cd contracts/htlc && forge build -q)
token_bytecode="$(python3 -c "import json; print(json.load(open('contracts/htlc/out/MockErc20.sol/MockErc20.json'))['bytecode']['object'])")"
token="$(cast send --rpc-url "$rpc_url" --private-key "$taker_key" --create "$token_bytecode" --json |
  python3 -c "import json,sys; print(json.load(sys.stdin)['contractAddress'])")"
cast send --rpc-url "$rpc_url" --private-key "$taker_key" "$token" "mint(address,uint256)" "$taker_addr" 10000000 >/dev/null
echo "usdc-live-dry-run: mock token $token minted 10 USDC-equivalent to taker $taker_addr"

# --network is a no-op here since --rpc-url/--token are always given explicitly below (a
# throwaway local token has no real network), but passing it anyway exercises the same
# "--network plus explicit overrides" shape usdc-live.sh itself now uses, and proves the
# flag doesn't break anything when combined with overrides.
ops() { cargo run -q -p swap-chain-evm --features live --example sepolia_ops -- --network sepolia --rpc-url "$rpc_url" --token "$token" "$@"; }

echo "usdc-live-dry-run: sepolia_ops deploy (the exact command usdc-live.sh runs)"
out="$(SWAP_EVM_KEY_HEX="$taker_key" ops deploy)"
htlc="$(sed -n 's/^htlc_address: //p' <<<"$out")"
[[ -n "$htlc" ]] || die "deploy failed: $out"
echo "usdc-live-dry-run: deployed htlc=$htlc"

echo "usdc-live-dry-run: sepolia_ops balances (dry-run mode: no key)"
ops balances --addr "$taker_addr"

echo "usdc-live-dry-run: sepolia_ops send-eth (funding the maker, as usdc-live.sh does)"
SWAP_EVM_KEY_HEX="$taker_key" ops send-eth --to "$maker_addr" --wei 20000000000000000

echo "usdc-live-dry-run: sepolia_ops send-usdc (funding the maker, as usdc-live.sh does)"
SWAP_EVM_KEY_HEX="$taker_key" ops send-usdc --to "$maker_addr" --units 2000000

echo "usdc-live-dry-run: UsdcBackend lock/claim/refund against anvil (live_sepolia_lock_claim" \
  "hardcodes the real Sepolia USDC address and so cannot itself run here)"
cargo test -q -p swap-chain-evm --all-features

echo "usdc-live-dry-run: a full DIVI<->USDC swap, both directions, through the engine" \
  "(mock DIVI + a real UsdcBackend over a second anvil instance tests/usdc.rs spawns itself)"
cargo test -q -p divi-swap --test usdc

echo "usdc-live-dry-run: OK — deploy, fund, lock/claim/refund and a full swap all proved" \
  "against anvil. usdc-live.sh's real-network equivalents are the only steps left."
