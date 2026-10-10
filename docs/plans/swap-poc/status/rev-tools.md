# rev-tools lane status

- done: e2e.sh `--offer <divi-btc-testnet|btc-divi-testnet>` (reverse: state dir rev-<scenario>-<backend|deployed>, txid prefix rev_/deployed_rev_, taker `--divi-wallet`, reverse result keys, live preflight)
- done: chaos/driver.py `--offer` passthrough (reverse: taker DIVI wallet, no BTC-settle wait, divi_refund_by_taker)
- done: check-rev-live.sh (rev-live.md keys, deployed_ alternates)
- running: nothing
- broken: nothing known
- left: nothing (check-rev-tools.sh passes); live reverse runs are the orchestrator's
- decisions: preflight checks the maker advertises the offer and its BTC backend has a tip; maker BTC balance is not in the API, so it is checked only when E2E_MAKER_BTC_ADDRESS is set; taker DIVI balance is parsed as the first integer on a `divi` line of `divi-swap balance` (rev-cli to confirm the format)
- last_sha: 6355c07
