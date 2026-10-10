# rev-cli status
- done: divi-swapd default offers (both directions) + config tests; test World/offers/api tests for both directions; divi-swap `--divi-wallet`/`--divi-scan-from` (wallet.rs: path refused inside git tree, 0600, resume from cursor), `balance` subcommand, `txids` direction-aware (txids.rs, `txids_reverse_keys`), ClaimGate generalised to the maker-leg chain (`--never-claim`/`--claim-not-before` work in both directions)
- running: -
- broken: e2e_mock_rev_happy_path, e2e_mock_rev_refund fail until rev-engine lands (Taker/Maker engine still forward-only on main)
- left: rebase on rev-engine; adapt TakerRecord field names (btc_htlc/divi_htlc -> role-based) in flow.rs `release` and txids.rs; rerun check-rev-cli.sh
- last_sha: (see git log)
- decisions: DIVI wallet file mode via process umask 0o077 using an extern "C" umask declaration (no new dep) plus chmod of an existing file; BTC balance read from esplora /address/{addr} (chain+mempool funded-spent) since BtcBackend has no balance; `balance` needs --backend live; default config ships both offers at the same rate/limits; wallet is scanned to tip before lock/run/balance only when --divi-wallet is given; --divi-wallet with mock backend is an error
- needs: deploy/divi-swapd/divi-swapd.toml.example should add the reverse offer `btc-divi-testnet` (direction = "taker_pays_divi"); orchestrator live run should pass --divi-scan-from 343648
- parked: -
