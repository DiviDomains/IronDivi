# Lane divi status

- done: DiviBackend (rpc.rs, wallet.rs, lib.rs), 8 offline tests incl. wiremock, live_fund_claim_refund passed (fund, claim, refund all confirmed)
- running: nothing
- broken: none
- left: nothing
- live_fund_txid: db0078c0b400125dc5681341b887cd405ffb5e67faf539c9464b341d7c834702
- live_fund_b_txid: b65825714e520eb72cc511c532431a4624f23b028cee8414b6aa7f64f5f4694f
- live_claim_txid: b16e7eb7af3fd20d08741c0759d02d45c6498e472e69251ee8a55e434f4c3f95
- live_refund_txid: 454c1c1eedb9e5ae92c1954813a447d433c6bae455bc1b5ffcc4d8dec4b184b2
- decisions: MTP = median of last 11 block times (proxy returns mediantime null); wallet is local JSON + block scan since proxy has no address/spent index; seeded from 03f9… only, outputs of 6ff5… excluded
- note: stop-hook fmt/clippy/test FAILs were PATH only (cargo lives in /opt/homebrew/opt/rustup/bin)
- last_sha: d3bd5e9
