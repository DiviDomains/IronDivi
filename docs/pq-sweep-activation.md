# Post-quantum sweep planning before DIP-PQ-3 activation

`planpqsweep` (and the web interface's `/api/pq/sweep-plan` route, which calls it) plans a
voluntary move of exposed classical coins into vault or post-quantum outputs.
It never signs, broadcasts or changes the wallet.

## Why PQ outputs are withheld

`P2PQPKH` (34 B) and `PQ_STAKING_VAULT` (74 B) outputs only get their spending
rules from `DIP-PQ-3` (`PostQuantumWitnessAndVaults`). Neither client enforces
that fork yet:

- Divi Core declares `Fork::PostQuantumWitnessAndVaults` in
  `divi/src/ForkActivation.cpp`, but no consensus code consults it.
- IronDivi's `divi-storage::fork_activation` has no such fork.

Until both clients enforce it, coins sent to these scripts have no consensus
spending rules for the owner's keys to rely on. A wallet must not hand out a transaction that creates or spends
them.

## Behaviour

`divi_wallet::pq_sweep::PqSweepPlanConfig::pq_output_activation` defaults to
`PqOutputActivation::Inactive`. While it is inactive:

| Plan | `plan_voluntary_pq_sweep` | `planpqsweep` reply |
|---|---|---|
| `PQ_STAKING_VAULT` or `P2PQPKH` destination | `Err(PqOutputsNotActive)` | estimate only |
| Classical `STAKING_VAULT` and every batch is at least 10,000 DIVI | plan | signable plan |
| Classical `STAKING_VAULT` where any batch would fall back to `P2PQPKH` (mixed) | `Err(PqOutputsNotActive)` for the whole plan | estimate only |
| `resweep_pq_native = true` | PQ-native inputs are skipped | (not exposed over RPC) |

A signable reply has `"signable": true`, plus `txid`, `raw_tx_hex` and output
`script_pubkey` for each batch. An estimate-only reply has `"signable": false`,
`pq_output_activation`, `withheld_reason`, and a `requires_pq_outputs` flag and
output `kind` (`staking_vault`, `pq_staking_vault` or `p2pqpkh`) for each batch.
It has no `txid`, `raw_tx_hex` or `script_pubkey`. The fee, weight, input
selection, skipped UTXO and posture figures are the same as in the plan that
would be produced after activation.

`getpqposture` is unchanged.

`estimate_voluntary_pq_sweep` gives library callers the same estimate. It
returns no transactions or scripts.

## Enabling after activation

`WalletRpc::pq_output_activation` (`crates/divi-rpc/src/wallet.rs`) returns
`Inactive`. Change it to read the chain tip's fork state only when:

1. `Fork::PostQuantumWitnessAndVaults` exists in IronDivi consensus with the
   same activation as Divi Core;
2. both clients enforce `DIP-PQ-3` script and witness rules at that fork; and
3. the mixed-client gauntlet in `docs/plans/post-quantum-lockstep.md` Phase 3
   (`P3.4`) has passed.

No consensus or activation code is changed by this gate.
