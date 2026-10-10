# rev-engine lane status

- done: MakerRecord/TakerRecord renamed role-based with serde aliases for old btc_*/divi_* names; Maker and Taker engines direction-generic (taker leg on direction.taker_chain(), maker leg on maker_chain()); staking invariant enforced on both backends; tests/engine.rs runs every scenario in both directions plus forward_records_still_load against the real fixtures; DECISIONS #9
- running: final fmt/clippy/test run
- broken: nothing known
- left: check-rev-engine.sh
- last_sha: (set at commit)
- decisions: reverse timeout profiles unchanged (DECISIONS #9); window-too-short measured on the taker-leg chain clock; Taker::new signature kept (divi, btc) — legs picked by quote.direction
- needs: nothing
