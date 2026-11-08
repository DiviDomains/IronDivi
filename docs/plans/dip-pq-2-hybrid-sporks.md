# DIP-PQ-2: Lockstep Hybrid secp256k1 + LMS-SHA256-M32-H10 Spork Authority & Cutoff Policy

- **DIP:** `DIP-PQ-2`
- **Track:** Track 7D Phase 2 (`P2.1` Dual-Signed Spork Messages & `P2.2` Consensus Cutoff for `secp256k1`-Only Sporks)
- **Coordination Tier:** Tier C (Strict Dual-Client P2P & Governance Lockstep)
- **Status:** Active Specification & Reference Implementation (2026-11-08)
- **Applies To:** Canonical C++ Divi Core (`DiviProject/Divi`, `divid` v3.0.0+) and Rust IronDivi (`DiviDomains/IronDivi`, `irondivid` v0.2.9+)
- **Parent Architecture Document:** [`docs/plans/post-quantum-lockstep.md`](./post-quantum-lockstep.md) (§2.2 #1, §3 Tier C #2, §5 Candidate PQ Trade-Offs, §6 Phase 2 `P2.1` & `P2.2`)
- **Companion Specifications:**
  - [`docs/plans/dip-pq-0-hndl-and-crypter.md`](./dip-pq-0-hndl-and-crypter.md)
  - [`docs/plans/dip-pq-1-algorithms-and-hd.md`](./dip-pq-1-algorithms-and-hd.md)

---

## 1. Abstract & Threat Model (`strSporkKey` Exposure)

In Divi Core (`divi/src/chainparams.cpp` & `divi/src/spork.cpp`) and IronDivi (`crates/divi-network/src/spork.rs`), network governance parameters (`SPORK_2_SWIFTTX_ENABLED` through `SPORK_16_LOTTERY_TICKET_MIN_VALUE`) are authenticated by a single hardcoded compressed 33-byte `secp256k1` public key (`strSporkKey`):

- **Divi Mainnet:** `02c1ed5eadcf6793fa22840febfbd667fabbabc48ddd75c2d228662d65e292eb00`
- **Divi Testnet / Regtest:** `034ffa41e5cffdd009f3b34a3e1482ec82b514bb218b7648948b5858cc5c035adb`

Because `strSporkKey` is a raw compressed `secp256k1` curve point compiled directly into every node binary—and every historical `CSporkMessage` signature uses compact public-key recovery (`CPubKey::RecoverCompact`)—`strSporkKey` is permanently exposed on-wire and in source code. A cryptanalytically relevant quantum computer (CRQC) capable of running Shor's elliptic-curve discrete logarithm algorithm on `secp256k1` could recover the classical Spork private key offline and broadcast forged `spork` messages (e.g., altering `SPORK_13_BLOCK_PAYMENTS`, `SPORK_14_TX_FEE`, `SPORK_15_BLOCK_VALUE`, `SPORK_16_LOTTERY_TICKET_MIN_VALUE`, or `SPORK_9_SUPERBLOCKS_ENABLED`).

Unlike UTXO script witnesses (`DIP-PQ-3`) or Proof-of-Stake block headers (`DIP-PQ-4`), Spork messages:
1. Are broadcast rarely (dozens of times over the entire lifetime of the chain rather than thousands of times per block),
2. Are signed by a single coordinated governance authority rather than millions of uncoordinated end-user wallets, and
3. Already serialize their signature inside a variable-length `CompactSize`-prefixed byte vector (`std::vector<unsigned char> vchSig` in `divi/src/spork.h` and `SporkMessage::signature: Vec<u8>` in `crates/divi-network/src/messages.rs`).

`DIP-PQ-2` upgrades Spork authentication in lockstep across C++ `divid` and Rust `irondivid` using a **hybrid classical + stateful hash-based post-quantum signature (`secp256k1` + `LMS-SHA256-M32-H10`)** whose security rests solely on `SHA-256` / `SHA-512` preimage resistance ($2^{128}$ post-quantum Grover security, zero algebraic lattice assumptions), deployed via a 3-stage cutoff policy (`ClassicalOnly` $\to$ `HybridOptional` $\to$ `HybridRequiredAfter`).

---

## 2. Wire Format: `CSporkMessage` v1 (`65 B`) and v2 (`2,577 B`)

### 2.1 Existing P2P Serialization Invariant

Both C++ `divid` (`divi/src/spork.h:80-89`) and Rust `irondivid` (`crates/divi-network/src/messages.rs:544-576`) serialize a `"spork"` P2P message as:

```text
+-------------------+-----------------------------------+---------------------+-----------------------------------+
| nSporkID (i32 LE) | CompactSize(|strValue|) || bytes  | nTimeSigned (i64 LE)| CompactSize(|vchSig|) || vchSig   |
|     4 bytes       |        1..9 + N bytes             |       8 bytes       |       1 or 3 + |vchSig| bytes     |
+-------------------+-----------------------------------+---------------------+-----------------------------------+
```

Furthermore, in both implementations, the inventory / database identity hash of a Spork (`CSporkMessage::GetHash()` with `SER_GETHASH` in C++, `SporkMessage::hash()` in Rust) is `Hash256 = SHA256(SHA256(nSporkID || strValue || nTimeSigned))`, which **excludes `vchSig`**.

### 2.2 Dual-Format `vchSig` / `SporkMessage.signature`

`DIP-PQ-2` defines two exact canonical byte lengths for `vchSig` (`SporkMessage::signature`):

| Format Version | Byte Length (`\|vchSig\|`) | `CompactSize` Prefix | Wire Layout | Description |
|---|---|---|---|---|
| **Legacy `v1`** (`CLASSICAL_SPORK_SIG_LEN`) | **`65` bytes** | `0x41` (`1` byte) | `sig_secp256k1[65]` | Classical compact `secp256k1` recovery signature (`header[1] \|\| r[32] \|\| s[32]`, `header` $\in [31, 34]$) over ASCII decimal `format!("{}{}{}", spork_id, value, time_signed)` with `"DarkNet Signed Message:\n"`. |
| **Hybrid `v2`** (`HYBRID_SPORK_SIG_LEN`) | **`2,577` bytes** (`65 + 2,512`) | `0xfd 0x11 0x0a` (`3` bytes) | `sig_secp256k1[65] \|\| sig_lms_m32_h10[2512]` | Concatenation of the standard 65-byte classical `secp256k1` compact signature followed immediately by the 2,512-byte `LMS-SHA256-M32-H10` (`LMOTS-SHA256-N32-W4`, `scheme_id = 0x04`) post-quantum signature (`DIP-PQ-1` §2.1 #4, §3.5). |

Any `SporkMessage` whose `signature.len()` is neither `65` nor `2,577` (for example `0`, `64`, `66`, `2,512`, `2,576`, or `2,578` with a trailing padding byte) MUST be rejected immediately before any cryptographic verification (`SporkVerifyError::InvalidSignatureLength`).

---

## 3. Cryptographic Binding & Prehash Construction (`"DIVI-SPORK-PAYLOAD-V1"` $\to$ `"Divi-PQ-Spork-v1"`)

### 3.1 Preventing Component Stripping & Substitution

In a hybrid signature scheme (`sig_secp256k1[65] || sig_lms_m32_h10[2512]`), signing the Spork fields independently with `secp256k1` and `LMS` would allow an attacker who compromises only the classical `secp256k1` key (or exploits signature malleability) to replace `sig_secp256k1[65]` while reusing the valid `sig_lms_m32_h10[2512]` suffix.

To cryptographically bind the post-quantum `LMS` signature to the exact Spork parameters **and** the exact 65-byte classical `secp256k1` signature, `DIP-PQ-2` defines a 32-byte `payload_hash_256` using the 21-byte ASCII domain prefix **`"DIVI-SPORK-PAYLOAD-V1"`** (`444956492d53504f524b2d5041594c4f41442d5631`):

#### Case A: Integer-Valued Sporks (`strValue` is a canonical base-10 signed 64-bit integer)

For all single-value Sporks (`SPORK_2` through `SPORK_12`, or any Spork where `strValue` parses as a canonical base-10 `i64` integer `v` such that `v.to_string() == strValue`), the preimage is exactly **106 bytes**:

$$\text{payload\_hash\_256} = \text{SHA256}\Bigl(\texttt{"DIVI-SPORK-PAYLOAD-V1"} \text{ (21 B)} \parallel \text{i32\_le}(\text{spork\_id}) \text{ (4 B)} \parallel \text{i64\_le}(\text{value}) \text{ (8 B)} \parallel \text{i64\_le}(\text{time\_signed}) \text{ (8 B)} \parallel \text{sig\_secp256k1} \text{ (65 B)}\Bigr)$$

#### Case B: Multi-Value String Sporks (`SPORK_13`–`SPORK_16` semicolon-delimited strings)

For multi-value Sporks (`SPORK_13_BLOCK_PAYMENTS`, `SPORK_14_TX_FEE`, `SPORK_15_BLOCK_VALUE`, `SPORK_16_LOTTERY_TICKET_MIN_VALUE`) whose `strValue` is a non-integer string (e.g., `"5000;100"`), the preimage encodes the UTF-8 byte length as `u64_le` followed by a `0xff` separator byte and the raw `strValue` bytes (`>= 107` bytes total, strictly disjoint in byte length from the 106-byte Case A preimage):

$$\text{payload\_hash\_256} = \text{SHA256}\Bigl(\texttt{"DIVI-SPORK-PAYLOAD-V1"} \text{ (21 B)} \parallel \text{i32\_le}(\text{spork\_id}) \text{ (4 B)} \parallel \text{u64\_le}(\lvert\text{strValue}\rvert) \text{ (8 B)} \parallel \texttt{0xff} \text{ (1 B)} \parallel \text{strValue} \parallel \text{i64\_le}(\text{time\_signed}) \text{ (8 B)} \parallel \text{sig\_secp256k1} \text{ (65 B)}\Bigr)$$

### 3.2 `DIP-PQ-1` `SporkV1` 64-Byte `SHA-512` Signing Prehash

The 32-byte `payload_hash_256` is passed as `ctx_payload` into `DIP-PQ-1` §4.2 `compute_pq_signing_prehash` under `PqDomainTag::SporkV1` (`"Divi-PQ-Spork-v1"`, 16 bytes) and `PqSchemeId::LmsSha256M32H10` (`0x04`):

$$\text{pk\_hash256} = \text{ pq\_key\_hash\_256}\bigl(\texttt{0x04},\ \text{pq\_spork\_pubkey}[60]\bigr) = \text{SHA256}\bigl(\texttt{0x04} \parallel \text{pq\_spork\_pubkey}[60]\bigr)$$

$$\text{prehash\_msg} = \text{SHA512}\Bigl(\texttt{0x10} \parallel \texttt{"Divi-PQ-Spork-v1"} \parallel \text{network\_magic}[4] \parallel \texttt{0x04} \parallel \text{pk\_hash256}[32] \parallel \text{payload\_hash\_256}[32]\Bigr)$$

The resulting 64-byte `prehash_msg` is signed and verified via `LMS-SHA256-M32-H10` (`LmsPrivateKey::sign_prehash` and `verify_lms_prehash` in `crates/divi-crypto/src/pq/mod.rs` and `divi_pq_verify_lms_prehash` in `divi/src/pqcrypto/pq_verify.c`).

---

## 4. Three-Stage Transition & Cutoff Policy (`SporkAuthPolicy`)

To allow seamless rolling upgrades across the P2P network without hard-forking P2P handshakes during node deployment, `DIP-PQ-2` defines a 3-stage verification policy (`SporkAuthPolicy`):

```text
Stage 1: ClassicalOnly             Stage 2: HybridOptional                Stage 3: HybridRequiredAfter
──────────────────────────────  ►  ────────────────────────────────────  ►  ────────────────────────────────────────────
Legacy v1 (65 B): ACCEPTED         Legacy v1 (65 B): ACCEPTED             If time_signed < cutoff_time_signed:
Hybrid v2 (2577 B):                Hybrid v2 (2577 B):                      Legacy v1 (65 B): ACCEPTED
  secp256k1 verified +               secp256k1 MUST verify AND              Hybrid v2 (2577 B): BOTH MUST verify
  LMS canonical format checked       LMS-SHA256-M32-H10 MUST verify       If time_signed >= cutoff_time_signed:
                                     against pq_spork_pubkey                Legacy v1 (65 B): REJECTED (Misbehaving 100)
                                                                            Hybrid v2 (2577 B): BOTH MUST verify
```

### 4.1 Stage Definitions

1. **`SporkAuthPolicy::ClassicalOnly` (Default Pre-`DIP-PQ-2` Compatibility Mode):**
   - A 65-byte `v1` Spork is accepted if and only if `sig_secp256k1[65]` recovers to the configured compressed `strSporkKey`.
   - A 2,577-byte `v2` Spork is accepted if and only if its 65-byte prefix `sig_secp256k1[0..65]` recovers to `strSporkKey` **and** its 2,512-byte suffix `sig_lms[65..2577]` passes strict `LMS-SHA256-M32-H10` canonical header/bounds validation (`PqSchemeId::LmsSha256M32H10.validate_signature_encoding`). This guarantees that even a node without a configured 60-byte `pq_spork_pubkey` never accepts or relays malformed garbage in the 2,512-byte suffix.
2. **`SporkAuthPolicy::HybridOptional { pq_spork_pubkey: [u8; 60], network_magic: [u8; 4] }` (Phase `P2.1` Rollout):**
   - A 65-byte `v1` Spork is accepted if `sig_secp256k1[65]` is valid for `strSporkKey` (`Ok(SporkAuthKind::ClassicalV1)`).
   - A 2,577-byte `v2` Spork is accepted if and only if **both** `sig_secp256k1[0..65]` is valid for `strSporkKey` **and** `sig_lms[65..2577]` is cryptographically valid for `pq_spork_pubkey` under `network_magic` (`Ok(SporkAuthKind::HybridV2 { lms_leaf_q })`). If either component fails, the Spork is rejected and the sending peer receives `BAD_SPORK_SCORE` (`100`).
3. **`SporkAuthPolicy::HybridRequiredAfter { pq_spork_pubkey: [u8; 60], network_magic: [u8; 4], cutoff_time_signed: i64 }` (Phase `P2.2` Post-Cutoff Enforcement):**
   - For historical / pre-cutoff Sporks (`spork.time_signed < cutoff_time_signed`) replayed during initial sync or loaded from `sporkdb`, verification follows `HybridOptional` rules (both valid `65 B` `v1` and valid `2,577 B` `v2` Sporks are accepted).
   - For all Sporks signed at or after the cutoff timestamp (`spork.time_signed >= cutoff_time_signed`), a 65-byte classical-only Spork MUST be rejected with `SporkVerifyError::MissingPostQuantumSignatureAfterCutoff`, and only a valid 2,577-byte `HybridV2` Spork passing **both** `secp256k1` and `LMS-SHA256-M32-H10` verification is accepted.
   - Because `CSporkManager::ProcessSpork` / `SporkManager::handle_spork` only replaces an active single-value Spork when `spork.time_signed > active.time_signed`, once a post-cutoff Spork (with `time_signed >= cutoff_time_signed`) is active—or once `cutoff_time_signed` has passed—no attacker who recovers only the classical `secp256k1` `strSporkKey` can ever supersede an active Spork or inject a new multi-value Spork entry with `time_signed >= cutoff_time_signed`.

---

## 5. Stateful `LMS` Leaf-Index Monotonicity & Rollback Detection

`LMS-SHA256-M32-H10` provides $2^{10} = 1,024$ one-time signature leaves ($q \in [0, 1023]$), encoded in big-endian bytes `sig_lms[0..4]` (`sig[65..69]` of the 2,577-byte hybrid `vchSig`).

### 5.1 Signer State Persistence Rules

1. The offline Spork signing tool (`LmsPrivateKey`) MUST advance `next_leaf_q` monotonically (`0, 1, 2, ..., 1023`) and fsync the updated counter before outputting any signed `CSporkMessage` v2 payload.
2. When `next_leaf_q >= 1024`, `LmsPrivateKey::sign_prehash` returns `Err(PqError::LmsKeyExhausted(1024))` and refuses to sign.

### 5.2 Validator Leaf-Index Tracking (`last_lms_leaf_q`)

1. Every node's `SporkManager` tracks:
   - `last_lms_leaf_q: Option<u32>`: the highest verified `LMS` leaf index $q$ observed across all accepted `HybridV2` Sporks, and
   - `spork_lms_leaf_q: HashMap<i32, u32>`: the last verified `LMS` leaf index $q$ per `spork_id`, plus `(q -> spork_hash)` mapping to detect conflicting reuse of the same one-time leaf $q$ on two distinct Spork messages.
2. If a valid `HybridV2` Spork arrives with a leaf index $q$ that was already used to sign a **different** `spork.hash()`, or with $q \le \text{spork\_lms\_leaf\_q}[spork\_id]$ for a newer `time_signed`, `SporkManager` logs a high-priority security warning (`tracing::warn!`) flagging potential signer state rollback or key-state desynchronization.

---

## 6. Verification & Cross-Client Test Matrix

1. **Unit & Adversarial Suite (`crates/divi-network/src/spork.rs`):**
   - Legacy `65 B` `v1` acceptance under `ClassicalOnly`, `HybridOptional`, and `HybridRequiredAfter` (when `time_signed < cutoff_time_signed`).
   - Hybrid `2,577 B` `v2` signing (`sign_hybrid_spork_lms` / `attach_lms_signature`), P2P wire `serialize()` / `deserialize()` round-trip, and verification under `ClassicalOnly`, `HybridOptional`, and `HybridRequiredAfter`.
   - Post-cutoff rejection (`MissingPostQuantumSignatureAfterCutoff`) of `65 B` `v1` Sporks when `time_signed >= cutoff_time_signed` (both exact boundary `time_signed == cutoff_time_signed` and `time_signed > cutoff_time_signed`).
   - Adversarial bit-flip & substitution tests:
     - Bit-flipped classical `secp256k1` portion (`sig[10] ^= 0x01`) rejected as `InvalidClassicalSignature`.
     - Bit-flipped post-quantum `LMS` portion (`sig[65 + 100] ^= 0x01`) rejected as `InvalidPostQuantumSignature(PqError::VerificationFailed)`.
     - Out-of-range `LMS` leaf index (`q = 1024`) or non-zero reserved tail (`sig[2573..2577] != 0`) rejected as `NonCanonicalSignature`.
     - Wrong `network_magic` (e.g., signed for `TESTNET_MAGIC`, verified under `MAINNET_MAGIC`) rejected.
     - Tampered `spork_id`, `value` (both integer and multi-value `"5000;100"`), or `time_signed` rejected.
     - Trailing byte (`2,578 B`) or truncated byte (`2,576 B`, `64 B`) rejected as `InvalidSignatureLength`.
     - **Classical signature substitution attack:** re-signing the same `(spork_id, value, time_signed)` with a different `secp256k1` signature (or mutated recovery header) while keeping the original `2,512 B` `LMS` signature fails `LMS` verification because `payload_hash_256` commits to `sig_secp256k1[65]`.
     - `SporkManager` end-to-end P2P relay, peer misbehavior scoring (`BAD_SPORK_SCORE = 100`) on post-cutoff `v1` or forged `v2` Sporks, `ChainDatabase` persistence round-trip of `2,577 B` hybrid Sporks, and `last_lms_leaf_q` tracking.
