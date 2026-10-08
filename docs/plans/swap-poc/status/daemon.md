# daemon lane status

- decisions: claim and refund each map to one Taker::step; CLI session ids kept in a `<db>.sessions.json` sidecar (no secrets) because frozen Store has no getter for the maker swap id; CLI split into lib+bin so daemon tests drive the taker in-process; mock backend mines a block every 5 s in the daemon; live backend bails cleanly until chain lanes land
- parked: none
- done: divi-swapd + divi-swap CLI; config matches deploy/divi-swapd/divi-swapd.toml.example (test parses it); all nine acceptance tests green incl. e2e; check-daemon.sh PASS
- broken: nothing
- decisions: [[offers]] optional, built-in testnet offer used when absent; path_prefix defaults empty (nginx strips /swap/)
- running: nothing
- left: wire DiviBackend into live_backends (bin/divi-swapd/src/main.rs) once swap-chain-divi lands; then a live smoke run
- needs: Cargo.lock gains one line ("bitcoin") for divi-swapd direct dep; orchestrator to land
- decisions: JSON logs on; BTC live backend built from [btc] (signet only, key via SecretRef, hex 32 bytes, zeroed after use); DIVI side still errors cleanly
- last_sha: c28d7fb
