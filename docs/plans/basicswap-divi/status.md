# BasicSwap × Divi — status

Scope: the **BasicSwap DEX** (https://basicswapdex.com, github.com/basicswap/basicswap) with Divi added as a coin.
This is separate from the Divi-native swap system (`divi-swapd`, see `../swap-poc/`).
Testnet only. No upstream PR without the owner's go.

## Where the work lives
- Code: the builder host (`~/code/divi-basicswap/basicswap`) (Divi added, modelled on PIVX). Report from the first builder: `~/code/divi-basicswap/REPORT.md` there.
- Request received by the orchestrator session 2026-10-13; builder dispatched ~15:25Z; the owner reversed an initial no-go ~15:50Z ("SegWit is not a blocker") and asked to see it working on testnet ~15:52Z.
- This session first saw the request on 2026-10-14 and initially misread it as a reporting request.

## State at 2026-10-14
- Done (builder): 4 regtest swap tests pass (PART↔DIVI both ways, DIVI↔BTC); divid synced on Divi testnet; interface checks on testnet.
- **Done 2026-10-14: a BasicSwap swap on the public Divi testnet.** 50 tDIVI for 0.00025 tBTC, node A to node B (separate machines, B in Docker), through the web UI. Both bids reached Completed in 7 min 21 s. Bid `000000006acfc61c9ee8cecea0b27b09e0ef524a21fd37cdf726724c`; locks `fdd1dc66…5a60` (seller side) and `f1e5d11b…f696` (buyer side). Screenshots and walkthrough are in the private artifact https://claude.ai/artifact/QfunsCc9wzgMNnieWTeaHm.

## Testnet run (in progress)
Goal: a visible swap, tDIVI ↔ tBTC (Bitcoin testnet3), between two BasicSwap nodes (a node cannot take its own offer).
- Funding: no Divi testnet faucet. tDIVI comes from the swap-poc testnet node (same source as the swap-poc). tBTC from the swap-poc taker wallet. No Particl testnet faucet exists, so PART↔DIVI is not an option.
- Node A: `~/bsx-a` on the builder host (prepared with `prepare.py --testnet --withcoins=bitcoin,divi`). Running; Divi synced, funded with 1000 tDIVI (txid `036490fc…`, confirming at last check).
- Node B: `~/bsx-b` on a second host, in Docker (its system Python is 3.10; BasicSwap needs 3.11). Running; Divi synced. BTC deposit address `tb1ql9nn8grqmw3e6rt87z9uye643fdekqatxf49kw`.
- tBTC for node B: sweeping the swap-poc taker wallet to that address with `btc_cltv_proof sweep` (key resolved from 1Password at run time; waits on a broker approval).
- Waiting on: Bitcoin testnet3 and Particl header sync on both nodes (BTC ~97% at last check).
- Next: node A offers DIVI for BTC (`ABS_LOCK_BLOCKS`), node B bids and accepts, watch the bid reach `SWAP_COMPLETED`; tunnel both web UIs (:13000) to the owner's machine.

## Bugs found by provisioning on a real testnet (beyond the 13 in REPORT.md)
14. `DIVIPrepare` wrote no `rpcuser`/`rpcpassword` (divid has no cookie auth and ignores `rpcauth`) and the base class wrote a `[test]` section divid does not parse; divid exited at start with "you must set an rpcpassword". The regtest harness wrote its own conf, so tests never hit it. Fix: `prepareDataDir` override, random per-run rpc password written to both `divi.conf` and `basicswap.json`.

## Open items for the owner (from REPORT.md)
- Signing identity on the builder host (commits would show Unverified on GitHub).
- `gh` token scopes to verify registered signing keys.
- `secret` CLI not installed on the builder host.
- Official Divi coin icons (`Divi.png`, `Divi-20.png`) missing.

## Testnet-only workarounds (do NOT carry to mainnet or upstream)
- `strict_swap_type: false` and the swap type forced to Secret Hash (Divi has no SegWit).
- `restrict_unknown_seed_wallets: false` (Divi wallet has no BasicSwap seed).
- BTC testnet `min_amount` lowered 0.001 to 0.0001 in `chainparams.py` on both nodes (uncommitted).
- BTC in Electrum light mode on both nodes instead of a full sync.
- Particl testnet is dead (particld stays in initial block download, so SMSG never relays). A hand-made relay script copied SMSG messages between the nodes; the swap protocol itself is unchanged.
- `maxtipage` and `minimumchainwork` lines added to both `particl.conf`; they had no effect and should be removed at the next particld restart.

## Display bugs seen
- Seller-side bid page shows the swap amounts with swapped labels, and tags the first lock as tBTC although it is the Divi lock.
- Divi coin icon missing.
