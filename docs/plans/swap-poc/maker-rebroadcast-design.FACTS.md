# FACTS — third-party claims behind maker-rebroadcast-design.md

This lane had no network access, so none of these could be checked against the vendor. Verdict
"could not verify" is a verdict; the URL is where to check. No claim here changes a code path.

| Claim | Verdict | Source URL | What the design says now |
|---|---|---|---|
| DIVI Core `getrawtransaction` without `txindex` answers only for mempool transactions (or via the coins view for unspent outputs), so a confirmed spent-output tx can read as -5 | could not verify | https://github.com/DiviProject/Divi | q4: the engine does not rely on it; `None` always means re-send, which is idempotent |
| `sendrawtransaction` of a transaction already in the chain answers "already in block chain" / "txn-already-known" | could not verify | https://github.com/DiviProject/Divi | q4: the wording is matched in `classify_broadcast_error` (`rpc.rs:174`); an unmatched wording would surface as a `Rejected`, not as lost funds |
