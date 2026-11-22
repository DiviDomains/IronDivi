# Spork authority per network

Sporks change consensus values: block value, payments, fees and lottery minimum (sporks 13 to 16). IronDivi accepts a spork only when it is signed by the key of the network it runs on. Where no key is mapped, IronDivi processes no sporks. Code: `crates/divi-network/src/spork.rs` (`SporkAuthority`, `spork_authority`, `SporkManager`).

## Authority table

| Network | Authority | Source |
|---|---|---|
| Divi mainnet | `Divi`, `02c1ed5e…92eb00` | Divi Core `chainparams.cpp` |
| Divi testnet, regtest | `Divi`, `034ffa41…5c035adb` | Divi Core `chainparams.cpp` |
| PrivateDivi testnet | `PrivateDivi`, `034ffa41…5c035adb` | PrivateDivi Core `408ad01e`, `divi/src/chainparams.cpp:444` |
| PrivateDivi regtest | `PrivateDivi`, `034ffa41…5c035adb` | Inherited by `CRegTestParams : CTestNetParams` (`chainparams.cpp:458`) |
| PrivateDivi mainnet | `Unmapped` | Relaunched on 2026-04-20 from Core `21de13166`. That revision is not available, so the key is unconfirmed. |
| Any other magic | `Unmapped` | — |

The pinned revision is `PRIVATEDIVI_REFERENCE_REVISION`. PrivateDivi Core has no `HybridSporkV2` fork (`ForkActivation.cpp`), so a PrivateDivi spork must carry a 65-byte compact signature that verifies under `SporkAuthPolicy::ClassicalOnly`, on receipt and at load, whatever policy `set_auth_policy` sets. A 2,577-byte hybrid signature is refused. The Divi V1/V2 (`DIP-PQ-2`) policy is unchanged.

### What the regtest evidence covers

The PrivateDivi regtest authority is the Core reference key, inherited from testnet. **The PrivateDivi regtest genesis is not confirmed.** IronDivi uses genesis `4b66fa19…` (nTime 1771075434, nonce 984952). Core `408ad01e` uses `0000056b7de5…` (nTime 1771041600, nonce 534730). Spork authentication does not depend on the genesis, but this mapping makes **no** claim that IronDivi regtest interoperates with a Core regtest node. The fixtures use generated keys and synthetic sporks only. No real spork key signs anything in the tests.

### Enabling PrivateDivi mainnet

PrivateDivi mainnet stays `Unmapped` until Human confirms the post-relaunch `strSporkKey`, either from Core `21de13166` `chainparams.cpp` or from a dated ruling. The pre-relaunch key at `408ad01e` (`02c1ed5e…`) is **not** assumed.

## Receipt

| Authority | A spork that is newer than the active one, or any multi-value spork |
|---|---|
| `Divi` | Behaviour unchanged. The signature must verify under the active policy. A bad signature scores 100 (`BAD_SPORK_SCORE`). A good one is stored, activated and relayed. |
| `PrivateDivi` | Same as Divi, against the pinned key with `ClassicalOnly`, as PrivateDivi Core's `ProcessSpork` does. |
| `Unmapped` | Ignored. It is not stored, activated, handed to the chain, relayed or served, and spork `inv`s are not requested. The peer is **not** scored, because honest PrivateDivi peers relay sporks that their own key accepted. The spork still counts toward the peer's spork sync, so block sync is not delayed. |

On an `Unmapped` network, consensus reads the default values for sporks 13 to 16. Since `-sporkkey` is checked against `spork_key`, a PrivateDivi testnet/regtest node now accepts the pinned key's WIF, as Core's `init.cpp:968-975` does, and still does not sign with it.

## Database reload

Earlier IronDivi releases stored PrivateDivi sporks without checking them. At start, each stored spork row (`spork_<id>`) is handled as follows:

| Authority | Stored row |
|---|---|
| `Divi` | Loaded unchecked, as Divi Core's `LoadSporksFromDB` loads it. Behaviour unchanged. |
| `PrivateDivi` | Loaded only if it decodes, re-encodes to the same bytes, holds a spork of the row's own id, and verifies. Otherwise it is **quarantined**: it is not loaded and not handed to the chain, and the row is left unchanged. |
| `Unmapped` | Always quarantined, including rows that do not decode or hold another id. The quarantine raises a **startup hold** (below). |

On `PrivateDivi` and `Unmapped` networks, a row that does not decode is quarantined (`QuarantineReason::Undecodable`), as is a row `spork_<id>` that holds a spork of another id (`QuarantineReason::IdMismatch`). Neither is treated as absent. On `Divi`, undecodable rows are skipped with a warning, as before.

A row that **cannot be read** (a database error, not a missing key) on a `PrivateDivi` or `Unmapped` network is recorded as unreadable. Its content is unknown, so it is never treated as absent or as part of a known set. `try_with_chain` returns `SporkStartError::Unreadable`, and no acknowledgement releases it. Repair or restore the chain database, or roll back the binary. A verified spork received later does not overwrite that row. On `Divi`, a read error is logged and skipped, as before.

Rows are never deleted. If a verified spork later replaces a quarantined row, the old bytes are first copied to `spork_quarantine_<id>`. If that key already holds bytes, they must equal the quarantined row. If they differ, or if the key cannot be read or written, neither row is replaced. The verified spork stays active in memory but is not persisted, and an ERROR is logged.

### Diagnostics

- Each quarantined row is logged at ERROR with its id, value, `time_signed` and reason.
- `SporkManager::quarantined()` returns the quarantined rows (raw bytes included). `SporkManager::store_hold()` returns the hold, if one applies.
- `SporkStoreHold`'s `Display` lists the rows, their SHA-256 fingerprint and the release options.

### Startup hold (`Unmapped` networks with stored sporks)

An existing PrivateDivi mainnet database may hold sporks that the previous release activated. Loading them would adopt values that nobody can verify. Silently running on defaults instead would change the active consensus values. Neither happens automatically:

- `SporkManager::try_with_chain(…, hold_ack)` returns `Err(SporkStartError::Held(SporkStoreHold))` until `hold_ack` equals the hold's fingerprint. Unreadable rows take precedence (`SporkStartError::Unreadable`) and cannot be acknowledged.
- `irondivid` (`Node::new`) calls `try_with_chain` with `IRONDIVI_SPORK_HOLD_ACK` and stops with `initialization error: spork store hold: …` (or `spork store unreadable: …`).
- `SporkManager::with_chain` logs the same reports at ERROR but does not stop.

The fingerprint covers the exact held rows. If the rows change, a new acknowledgement is required. The operator sets it with `IRONDIVI_SPORK_HOLD_ACK=<fingerprint>` (`SPORK_HOLD_ACK_ENV`).

A PrivateDivi testnet/regtest database with rows that fail verification is quarantined without a hold. Those networks carry no value, and verified sporks replace the rows during spork sync.

## Upgrade and rollback

1. **Before upgrading** a PrivateDivi node, record `spork show` and `spork active` from the old binary. These are the values it was running on.
2. **Upgrade.**
   - On PrivateDivi testnet/regtest, check the log for quarantined rows. After spork sync, `spork show` reports only values signed with the pinned key.
   - On PrivateDivi mainnet with stored sporks, the start is held. Choose one:
     - **Stay on the old binary** (rollback) until the mainnet key is confirmed and mapped.
     - **Accept defaults:** compare the recorded values with the defaults, get approval, then start with `IRONDIVI_SPORK_HOLD_ACK=<fingerprint>`. The rows stay in the database.
3. **Rollback** is a binary swap. Old releases read `spork_<id>` as before and ignore `spork_quarantine_<id>`. The only row that differs after an upgrade is one replaced by a verified spork, and its previous bytes are kept under `spork_quarantine_<id>`. Restoring it means copying those bytes back; nothing is restored automatically.
4. **After the mainnet key is mapped** (a code change), stored rows that verify load again. Rows that do not are quarantined without a hold.
