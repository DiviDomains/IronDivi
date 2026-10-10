# daemon lane status

- decisions: claim and refund each map to one Taker::step; CLI session ids kept in a `<db>.sessions.json` sidecar (no secrets) because frozen Store has no getter for the maker swap id; CLI split into lib+bin so daemon tests drive the taker in-process; mock backend mines a block every 5 s in the daemon; live backend bails cleanly until chain lanes land
- parked: none
- broken: nothing
- decisions: [[offers]] optional, built-in testnet offer used when absent; path_prefix defaults empty (nginx strips /swap/)
- decisions: JSON logs on; BTC live backend built from [btc] (signet only, key via SecretRef, hex 32 bytes, zeroed after use); DIVI side still errors cleanly
- done: live backends wired in divi-swapd and divi-swap CLI (DiviBackend + BtcBackend, keys via SecretRef); JSON logs; check-daemon.sh PASS
- running: nothing
- left: nothing; a full live swap against a real taker is the integration lane's job
- needs: Cargo.lock lines for new direct deps (divi-crypto, divi-wallet in both bins; bitcoin, zeroize in divi-swap-cli); orchestrator to land
- decisions: divi scan_from_height is applied at startup via DiviBackend::scan_blocks (failure is a warning); CLI live backend uses the default testnet RPC URL
- smoke: 2026-10-08 live run with op:// maker keys on port 18481: GET /healthz -> {"ok":true,"version":"0.2.4","divi":{"tip":339964,"error":null},"btc":{"tip":325424,"error":null}}; maker DIVI wallet scanned from 339800, balance 24799.91965 DIVI
- last_sha: 031504f
- decisions: bind first, DIVI wallet scan runs in the background in 500-block chunks; cursor (scanned_height) persisted in wallet_path after each chunk; resume from max(scan_from_height, cursor); failures retried every 30s and shown in healthz; quote/accept 503 'wallet scan in progress' and scheduler ticks deferred until done; /healthz ok=false until done, adds divi_scan{state,next_height,target_height,error}
- last_sha: a5b7a96
