# rev-cli status
- done: divi-swapd default offers (both directions) + config tests; test World/offers/api tests for both directions; divi-swap `--divi-wallet`/`--divi-scan-from` (wallet.rs: path refused inside git tree, 0600, resume from cursor), `balance` subcommand, `txids` direction-aware (txids.rs, `txids_reverse_keys`), ClaimGate generalised to the maker-leg chain (`--never-claim`/`--claim-not-before` work in both directions)
- running: -
- check: tools/swap-poc/check-rev-cli.sh PASS (engine landed, rev-cli field names adapted)
- broken: -
- left: -
- last_sha: 4ae2ed8
- decisions: DIVI wallet file mode via process umask 0o077 using an extern "C" umask declaration (no new dep) plus chmod of an existing file; BTC balance read from esplora /address/{addr} (chain+mempool funded-spent) since BtcBackend has no balance; `balance` needs --backend live; default config ships both offers at the same rate/limits; wallet is scanned to tip before lock/run/balance only when --divi-wallet is given; --divi-wallet with mock backend is an error
- needs: orchestrator live run should pass --divi-scan-from 343648
- parked: -
