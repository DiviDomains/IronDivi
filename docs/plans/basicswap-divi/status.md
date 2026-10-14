# BasicSwap × Divi — status

Scope: the **BasicSwap DEX** (https://basicswapdex.com, github.com/basicswap/basicswap) with Divi added as a coin.
This is separate from the Divi-native swap system (`divi-swapd`, see `../swap-poc/`).
Testnet only. No upstream PR without Bert's go.

## Where the work lives
- Code: `dev-a:~/code/divi-basicswap/basicswap` (Divi added, modelled on PIVX). Report from the first builder: `dev-a:~/code/divi-basicswap/REPORT.md`.
- Request received by the orchestrator session 2026-10-13; builder dispatched on dev-a ~15:25Z; Bert reversed an initial no-go ~15:50Z ("SegWit is not a blocker") and asked to see it working on testnet ~15:52Z.
- This session first saw the request on 2026-10-14 and initially misread it as a reporting request.

## State at 2026-10-14
- Done (builder): 4 regtest swap tests pass (PART↔DIVI both ways, DIVI↔BTC); divid synced on Divi testnet; interface checks on testnet.
- **Not done: a BasicSwap swap on the public Divi testnet.** No testnet BasicSwap node had been provisioned on dev-a.

## Testnet run (in progress)
Goal: a visible swap, tDIVI ↔ tBTC (Bitcoin testnet3), between two BasicSwap nodes (a node cannot take its own offer).
- Funding: no Divi testnet faucet. tDIVI comes from dnsdivi `/opt/divi-testnet/node5` (same source as the swap-poc). tBTC from the swap-poc taker wallet. No Particl testnet faucet exists, so PART↔DIVI is not an option.
- Node A: `dev-a:~/bsx-a` (prepared with `prepare.py --testnet --withcoins=bitcoin,divi`). Running; Divi synced, funded with 1000 tDIVI (txid `036490fc…`, confirming at last check).
- Node B: `hp2:~/bsx-b`, in Docker (hp2's system Python is 3.10; BasicSwap needs 3.11). Running; Divi synced. BTC deposit address `tb1ql9nn8grqmw3e6rt87z9uye643fdekqatxf49kw`.
- tBTC for node B: sweeping the swap-poc taker wallet to that address with `btc_cltv_proof sweep` (key resolved from 1Password at run time; waits on a broker approval).
- Waiting on: Bitcoin testnet3 and Particl header sync on both nodes (BTC ~97% at last check).
- Next: node A offers DIVI for BTC (`ABS_LOCK_BLOCKS`), node B bids and accepts, watch the bid reach `SWAP_COMPLETED`; tunnel both web UIs (:13000) to Bert's Mac.

## Bugs found by provisioning on a real testnet (beyond the 13 in REPORT.md)
14. `DIVIPrepare` wrote no `rpcuser`/`rpcpassword` (divid has no cookie auth and ignores `rpcauth`) and the base class wrote a `[test]` section divid does not parse; divid exited at start with "you must set an rpcpassword". The regtest harness wrote its own conf, so tests never hit it. Fix: `prepareDataDir` override, random per-run rpc password written to both `divi.conf` and `basicswap.json`.

## Open items for Bert (from REPORT.md)
- Signing identity on dev-a (commits would show Unverified on GitHub).
- `gh` token scopes to verify registered signing keys.
- `secret` CLI not installed on dev-a.
- Official Divi coin icons (`Divi.png`, `Divi-20.png`) missing.
