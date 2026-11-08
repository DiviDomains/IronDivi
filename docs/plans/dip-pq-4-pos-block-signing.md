# DIP-PQ-4: Post-Quantum Proof-of-Stake Block Signing (`vchBlockSig` Envelope, Coinstake Vault Binding & Cutoff Policy)

- **DIP:** `DIP-PQ-4`
- **Track:** Track 7D Phase 3 (`P3.3` Post-Quantum `vchBlockSig` Envelope & Staker Binding)
- **Coordination Tier:** Tier C (Strict Dual-Client Consensus, Block Header & Staker Lockstep)
- **Status:** Active Specification & Consensus-Inert Reference Implementation (2026-11-08)
- **Applies To:** Canonical C++ Divi Core (`DiviProject/Divi`, `divid` v3.0.0+) and Rust IronDivi (`DiviDomains/IronDivi`, `irondivid` v0.2.9+)
- **Parent Architecture Document:** [`docs/plans/post-quantum-lockstep.md`](./post-quantum-lockstep.md) (§2.2 #3, §3 Tier C #4, §5 Candidate PQ Trade-Offs, §6 Phase 3 `P3.3`)
- **Companion Specifications:**
  - [`docs/plans/dip-pq-0-hndl-and-crypter.md`](./dip-pq-0-hndl-and-crypter.md)
  - [`docs/plans/dip-pq-1-algorithms-and-hd.md`](./dip-pq-1-algorithms-and-hd.md)
  - [`docs/plans/dip-pq-2-hybrid-sporks.md`](./dip-pq-2-hybrid-sporks.md)
  - [`docs/plans/dip-pq-3-witness-and-vaults.md`](./dip-pq-3-witness-and-vaults.md)

---

## 1. Abstract & Threat Model (`vchBlockSig` `RecoverCompact` Exposure)

In classical Divi Proof-of-Stake blocks (`divi/src/BlockSigning.cpp` in C++ and `crates/divi-node/src/staker.rs` / `crates/divi-storage/src/chain.rs` in Rust), every minted PoS block carries a block signature vector `CBlock::vchBlockSig` (`Block::block_sig`) appended after the block's transaction list (`vtx`):

1. **Classical `P2PKH` (`TX_PUBKEYHASH`) & `STAKING_VAULT` (`TX_VAULT`) Coinstake Outputs:**
   - The staker signs the 32-byte block header hash (`block.GetHash()`) using a `65`-byte compact recoverable `secp256k1` signature (`CKey::SignCompact`).
   - Validators recover the 33-byte compressed `secp256k1` public key directly from `(block.GetHash(), block.vchBlockSig)` via `CPubKey::RecoverCompact` (`RecoverableSig::recover_from_hash`) and check that `Hash160(recovered_pubkey)` matches the 20-byte `pubkey_hash` in `coinstake.vout[1].scriptPubKey` (`solutions[0]` for `P2PKH`, `solutions[1]` = `vaultPubKeyHash` for `STAKING_VAULT`).
2. **Classical `P2PK` (`TX_PUBKEY`) Coinstake Outputs:**
   - `coinstake.vout[1].scriptPubKey` already contains the raw `secp256k1` public key, and `vchBlockSig` carries a `64..=73`-byte ASN.1 DER `secp256k1` signature (`0x30 ...`).

Transitioning Proof-of-Stake block authentication to post-quantum cryptography (`DIP-PQ-1` / `DIP-PQ-3`) introduces three fundamental structural requirements:

1. **No Public-Key Recovery (`RecoverCompact` Does Not Exist for Lattice Signatures):**
   Neither NIST FIPS 206 `FN-DSA-512` (`scheme_id = 0x02`, `897 B` public key, `666 B` signature) nor NIST FIPS 204 `ML-DSA-44` (`scheme_id = 0x01`, `1,312 B` public key, `2,420 B` signature) supports public-key recovery from `(message, signature)` alone. When a PoS block is staked by a 256-bit `DIP-PQ-3` output (`PQ_STAKING_VAULT` `74 B` or `P2PQPKH` `34 B`), `coinstake.vout[1].scriptPubKey` commits only to the 32-byte `SHA-256` key digest (`pq_address_key_hash_256`). Therefore, `vchBlockSig` MUST carry an explicit, non-malleable envelope containing `(scheme_id, pubkey_bytes, signature_bytes)`.
2. **Hot-Staker vs. Cold-Owner Key Separation in `PQ_STAKING_VAULT`:**
   A `DIP-PQ-3` `PQ_STAKING_VAULT` (`74` bytes) commits to two 32-byte key hashes: the cold owner key (`owner_pubkey_hash_256` in the `OP_IF` branch) and the hot coinstake manager key (`vault_pubkey_hash_256` in the `OP_ELSE OP_REQUIRE_COINSTAKE` branch). Consensus MUST enforce that `vchBlockSig` is signed **exclusively** by the hot `vault_pubkey_hash_256` key and MUST explicitly reject a `vchBlockSig` signed by `owner_pubkey_hash_256` (`ColdOwnerKeyForbiddenForBlockSigning`), ensuring that the cold owner private key (and even its public key) is never placed on an online staking node or revealed during block production.
3. **Header + Coinstake Outpoint Binding (`"DIVI-POS-BLOCK-V1"`):**
   Classical `SignCompact` signs only the 32-byte `block.GetHash()` (`SHA256d` of the 80-byte block header). Under `DIP-PQ-4`, the block signing payload binds `block_hash_32`, `coinstake_txid_32` (`block.vtx[1].GetHash()`), and `coinstake_vout_index_u32_le` (`1`) under the ASCII domain prefix `"DIVI-POS-BLOCK-V1"`, which is then passed as `ctx_payload` into `DIP-PQ-1` §4.2 `compute_pq_signing_prehash` under `PqDomainTag::BlockSigV1` (`"Divi-PQ-BlockSig-v1"`).

---

## 2. Wire Format of `PqBlockSigEnvelope` Inside `vchBlockSig`

### 2.1 Envelope Layout (Zero Internal Length Prefixes)

Inside a Proof-of-Stake block, `vchBlockSig` (`Block::block_sig`) is already framed on the wire by a single outer `CompactSize` byte-length prefix (`crates/divi-primitives/src/block.rs:239`).

When a PoS block is authenticated by a post-quantum signature (`DIP-PQ-4` `v1`), the contents of `vchBlockSig` are serialized as a fixed-layout `PqBlockSigEnvelope`:

```text
+--------------------+----------------------+--------------------+-------------------------------+-------------------------------+
| magic (1 byte)     | version (1 byte)     | scheme_id (1 byte) | pubkey_bytes (|pk| bytes)     | signature_bytes (|sig| bytes) |
| 0x50 ('P')         | 0x01                 | 0x01 or 0x02       | 1,312 B (0x01) or 897 B (0x02)| 2,420 B (0x01) or 666 B (0x02)|
+--------------------+----------------------+--------------------+-------------------------------+-------------------------------+
```

Because `scheme_id` in `DIP-PQ-1` §2 uniquely determines both `|pk|` (`pubkey_len()`) and `|sig|` (`signature_len()`), **zero internal `CompactSize` length prefixes are permitted inside `PqBlockSigEnvelope`**. Every valid `PqBlockSigEnvelope` has one of two exact total byte lengths:

| Scheme | `scheme_id` | Header (`magic \|\| version \|\| scheme_id`) | `\|pk\|` (`pubkey_bytes`) | `\|sig\|` (`signature_bytes`) | Total `vchBlockSig` Byte Length | Outer `CompactSize` Prefix |
|---|---|---|---|---|---|---|
| **NIST FIPS 206 `FN-DSA-512`** *(Recommended PoS Staker Default)* | `0x02` | `0x50 0x01 0x02` (`3 B`) | `897 B` | `666 B` | **`1,566` bytes** (`FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN`) | `0xfd 0x1e 0x06` (`3 B`) |
| **NIST FIPS 204 `ML-DSA-44`** | `0x01` | `0x50 0x01 0x01` (`3 B`) | `1,312 B` | `2,420 B` | **`3,735` bytes** (`ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN`) | `0xfd 0x97 0x0e` (`3 B`) |

### 2.2 Unambiguous Disjointness from Classical `vchBlockSig`

A validator inspecting `vchBlockSig` distinguishes classical `secp256k1` signatures from `DIP-PQ-4` post-quantum envelopes without ambiguity:

| Format | First Byte (`vchBlockSig[0]`) | Total Length (`\|vchBlockSig\|`) | Identification Rule |
|---|---|---|---|
| **Classical Compact `secp256k1`** (`P2PKH` / `STAKING_VAULT`) | `0x1b..=0x22` (`27..=34`) | **`65` bytes** | `vchBlockSig[0] != 0x50` and `len == 65` |
| **Classical ASN.1 DER `secp256k1`** (`P2PK`) | `0x30` (`48`) | **`64..=73` bytes** | `vchBlockSig[0] == 0x30` and `64 <= len <= 73` |
| **Post-Quantum `DIP-PQ-4` `v1` (`FN-DSA-512`)** | **`0x50` (`'P'`)** | **`1,566` bytes** | `vchBlockSig[0..3] == [0x50, 0x01, 0x02]` and `len == 1,566` |
| **Post-Quantum `DIP-PQ-4` `v1` (`ML-DSA-44`)** | **`0x50` (`'P'`)** | **`3,735` bytes** | `vchBlockSig[0..3] == [0x50, 0x01, 0x01]` and `len == 3,735` |

### 2.3 Forbidden Schemes in `BlockSigV1` (`DIP-PQ-1` §2 & §3.1 #2)

Per `DIP-PQ-1` §2:
- **`SLH-DSA-128s` (`scheme_id = 0x03`, `7,856 B` signature)** is restricted to `TxSigV1` (cold vault owner recovery) and `SporkV1`; it is **forbidden** in `BlockSigV1` (`PqError::SchemeForbiddenInDomain`) to prevent `7.9 KB` per-block header bloat and slow verification on 60-second block propagation.
- **`LMS-SHA256-M32-H10` (`scheme_id = 0x04`)** is restricted exclusively to `SporkV1` (`DIP-PQ-2`) and is **forbidden** in `BlockSigV1` (`PqError::SchemeForbiddenInDomain`).

Any `PqBlockSigEnvelope` carrying `scheme_id = 0x03` or `scheme_id = 0x04` MUST be rejected immediately during envelope decoding before any signature verification is attempted.

### 2.4 Canonical Public-Key & Signature Encoding Enforcement

During `PqBlockSigEnvelope::decode` (and `PqBlockSigEnvelope::new`), the decoder MUST enforce `DIP-PQ-1` §3 canonical encoding checks on both `pubkey_bytes` and `signature_bytes`:
1. **`FN-DSA-512` (`0x02`):**
   - `pubkey_bytes` (`897 B`): byte `0` MUST equal `0x09`, and all 512 unpacked 14-bit polynomial coefficients MUST satisfy $h_i < 12289$.
   - `signature_bytes` (`666 B`): byte `0` MUST equal `0x39` ($\log_2 n = 9$ fixed padded format), all 512 Golomb-Rice compressed $s_2$ coefficients MUST decode without `-0` or $|s_{2,i}| > 2047$, and all remaining padding bits through byte `665` MUST equal `0`.
2. **`ML-DSA-44` (`0x01`):**
   - `pubkey_bytes` (`1,312 B`): exact byte length `1,312`.
   - `signature_bytes` (`2,420 B`): all 1,024 unpacked 18-bit $z$ coefficients MUST satisfy $\|z\|_\infty < \gamma_1 - \beta = 130,994$, and the 84-byte hint section `sig[2336..2420]` MUST pass FIPS 204 `HintBitUnpack` monotonicity, strictly ascending index ordering, and zero-padding tail checks.

---

## 3. Coinstake Output Binding & Cold-Owner Key Protection

### 3.1 Staker Key Commitment (`staker_key_hash_256`)

Given a decoded `PqBlockSigEnvelope` with `(scheme_id, pubkey_bytes)`, the validator computes the 32-byte `DIP-PQ-1` §5.5 address/script key commitment:

$$\text{staker\_key\_hash\_256} = \text{pq\_address\_key\_hash\_256}(\text{scheme\_id},\ \text{pubkey\_bytes}) = \text{SHA256}\Bigl(\texttt{"Divi-PQ-PubKey-v1"} \parallel \text{u8}(\text{scheme\_id}) \parallel \text{pubkey\_bytes}\Bigr)$$

### 3.2 Binding to `coinstake.vout[1].scriptPubKey`

In a Divi Proof-of-Stake block, `block.vtx[1]` (`block.transactions[1]`) is the coinstake transaction (`tx.IsCoinStake()`), and `coinstake.vout[1]` is the primary staking output (`coinstake.vout[0]` is the empty marker output `scriptPubKey = ""`, `nValue = 0`).

`PqBlockSigEnvelope::verify_structural_and_staker_binding(&coinstake.vout[1].scriptPubKey)` enforces:

1. **`DIP-PQ-3` `PQ_STAKING_VAULT` (`74` bytes, `OP_IF 0x20 <owner_hash_256> OP_ELSE OP_REQUIRE_COINSTAKE 0x20 <vault_hash_256> OP_ENDIF OP_OVER OP_SHA256 OP_EQUALVERIFY OP_CHECKSIG`):**
   - **Rule 1 (Cold-Owner Key Strictly Forbidden):** If `staker_key_hash_256 == owner_hash_256`, the block MUST be rejected with `PqBlockSigError::ColdOwnerKeyForbiddenForBlockSigning { owner_hash_256, vault_hash_256 }`.
     - *Security Rationale:* Checking `staker_key_hash_256 == owner_hash_256` **before** `staker_key_hash_256 == vault_hash_256` guarantees two invariants simultaneously:
       1. A vault holder's cold `owner_hash_256` key can never be used to sign `vchBlockSig`, keeping the cold owner public key completely unrevealed behind `SHA-256`.
       2. Even if a misconfigured wallet constructs a degenerate `PQ_STAKING_VAULT` with `owner_hash_256 == vault_hash_256`, that output cannot mint blocks until funds are moved to a properly separated vault (`owner_hash_256 != vault_hash_256`).
   - **Rule 2 (Hot Vault Key Match):** `staker_key_hash_256` MUST equal `vault_hash_256`. Otherwise, the block is rejected with `PqBlockSigError::StakerKeyHashMismatch { expected: vault_hash_256, actual: staker_key_hash_256 }`.
2. **`DIP-PQ-3` `P2PQPKH` (`34` bytes, `OP_1 0x20 <addr_key_hash_256>`):**
   - `staker_key_hash_256` MUST equal `addr_key_hash_256`. Otherwise, the block is rejected with `PqBlockSigError::StakerKeyHashMismatch { expected: addr_key_hash_256, actual: staker_key_hash_256 }`.
3. **Any Other Script Type (Classical `P2PKH`, Classical `STAKING_VAULT`, `P2PK`, `P2SH`, Non-Standard):**
   - Rejected with `PqBlockSigError::UnsupportedCoinstakeScriptForPqBlockSig`.

---

## 4. Cryptographic Preimage & Domain-Separated Prehash (`"DIVI-POS-BLOCK-V1"` $\to$ `"Divi-PQ-BlockSig-v1"`)

### 4.1 85-Byte PoS Block Payload Preimage (`compute_pos_block_payload_hash`)

To prevent coinstake-outpoint grinding or header-context confusion across forks, `DIP-PQ-4` defines the 32-byte `block_signing_payload_hash_256` over an exact **85-byte** preimage:

```text
+-----------------------------------+-------------------------+-----------------------------+---------------------------------+
| ASCII Domain Prefix (17 bytes)    | block_hash (32 bytes)   | coinstake_txid (32 bytes)   | coinstake_vout_index (4 bytes)  |
| "DIVI-POS-BLOCK-V1"               | SHA256d(header_80)      | block.vtx[1].GetHash()      | u32_le (canonically 1 = 0x01..) |
+-----------------------------------+-------------------------+-----------------------------+---------------------------------+
```

$$\text{block\_signing\_payload\_hash\_256} = \text{SHA256}\Bigl(\texttt{"DIVI-POS-BLOCK-V1"} \text{ (17 B)} \parallel \text{block\_hash}[32] \parallel \text{coinstake\_txid}[32] \parallel \text{u32\_le}(\text{coinstake\_vout}) \text{ (4 B)}\Bigr)$$

### 4.2 64-Byte `DIP-PQ-1` `BlockSigV1` `SHA-512` Signing Prehash (`compute_pos_block_signing_prehash`)

The 32-byte `block_signing_payload_hash_256` is passed as `ctx_payload` into `DIP-PQ-1` §4.2 `compute_pq_signing_prehash` under `PqDomainTag::BlockSigV1` (`"Divi-PQ-BlockSig-v1"`, `19` bytes = `0x13`):

$$\text{pk\_hash256} = \text{pq\_key\_hash\_256}(\text{scheme\_id},\ \text{pubkey\_bytes}) = \text{SHA256}\bigl(\text{u8}(\text{scheme\_id}) \parallel \text{pubkey\_bytes}\bigr)$$

$$\text{prehash\_msg} = \text{SHA512}\Bigl(\texttt{0x13} \parallel \texttt{"Divi-PQ-BlockSig-v1"} \parallel \text{network\_magic}[4] \parallel \text{u8}(\text{scheme\_id}) \parallel \text{pk\_hash256}[32] \parallel \text{block\_signing\_payload\_hash\_256}[32]\Bigr)$$

The resulting 64-byte `prehash_msg` is signed and verified by the `scheme_id` algorithm (`FN-DSA-512` or `ML-DSA-44`).

---

## 5. Phased Activation & Cutoff Policy (`PosBlockAuthPolicy`)

`DIP-PQ-4` defines a four-stage consensus policy (`PosBlockAuthPolicy`) governing PoS block signature verification across the post-quantum transition:

```text
Stage 1: ClassicalOnly        Stage 2/3: DualAllowed / PqRequiredForPqOutputs   Stage 4: PqRequiredAllAfter { cutoff_block_time }
─────────────────────────── ► ──────────────────────────────────────────────── ► ──────────────────────────────────────────────────
Classical coinstake:          Classical coinstake (P2PKH / Vault / P2PK):        If block.nTime < cutoff_block_time:
  Classical vchBlockSig OK      Classical vchBlockSig OK                           Same as PqRequiredForPqOutputs
  PQ vchBlockSig REJECTED       PQ vchBlockSig REJECTED                          If block.nTime >= cutoff_block_time:
PQ coinstake:                 PQ coinstake (PQ_STAKING_VAULT / P2PQPKH):           Classical vchBlockSig REJECTED
  REJECTED                      PQ vchBlockSig REQUIRED & VERIFIED                 PQ coinstake + PQ vchBlockSig REQUIRED
                                Classical vchBlockSig REJECTED
```

1. **`PosBlockAuthPolicy::ClassicalOnly` (Pre-`DIP-PQ-4` Activation):**
   - Only classical `secp256k1` `vchBlockSig` on classical coinstake outputs (`P2PKH`, `STAKING_VAULT`, `P2PK`) is permitted.
   - Any `PostQuantumV1` `vchBlockSig` is rejected with `PqBlockSigError::PostQuantumBlockSigForbiddenBeforeActivation`.
2. **`PosBlockAuthPolicy::DualAllowed { network_magic }` / `PosBlockAuthPolicy::PqRequiredForPqOutputs { network_magic }` (Phase 3 Transition Window):**
   - Coinstake outputs using `DIP-PQ-3` `PQ_STAKING_VAULT` (`74 B`) or `P2PQPKH` (`34 B`) MUST authenticate the block with a valid `PostQuantumV1` `PqBlockSigEnvelope`; a classical `vchBlockSig` on a PQ coinstake output is rejected with `PqBlockSigError::MissingPostQuantumBlockSigForPqOutput`.
   - Coinstake outputs using classical `STAKING_VAULT` (`50 B`), `P2PKH` (`25 B`), or `P2PK` (`35/67 B`) continue to authenticate with a classical `secp256k1` `vchBlockSig`.
3. **`PosBlockAuthPolicy::PqRequiredAllAfter { network_magic, cutoff_block_time }` (Full Post-Quantum PoS Cutoff):**
   - For blocks with `block_time < cutoff_block_time`, verification follows `PqRequiredForPqOutputs`.
   - For blocks with `block_time >= cutoff_block_time`, classical `secp256k1` `vchBlockSig` is rejected with `PqBlockSigError::MissingPostQuantumBlockSigAfterCutoff { block_time, cutoff_block_time }`, requiring all newly minted PoS blocks to stake from 256-bit post-quantum outputs (`PQ_STAKING_VAULT` or `P2PQPKH`) signed with `FN-DSA-512` (`0x02`) or `ML-DSA-44` (`0x01`).

---

## 6. Canonical Phase 3 (`DIP-PQ-4`) Test Vectors

### Vector 1: PoS Block Payload Hash (`compute_pos_block_payload_hash`)

- **`block_hash` (32 B):** `[0x11; 32]`
- **`coinstake_txid` (32 B):** `[0x22; 32]`
- **`coinstake_vout` (`u32` LE):** `1` (`01000000`)
- **85-Byte Preimage Hex:**
  `444956492d504f532d424c4f434b2d56311111111111111111111111111111111111111111111111111111111111111111222222222222222222222222222222222222222222222222222222222222222201000000`

### Vector 2: `PqBlockSigEnvelope` Wire Lengths

- **`FN-DSA-512` (`scheme_id = 0x02`):**
  - Header: `500102` (`3` bytes)
  - Public key: `897` bytes (`pk[0] == 0x09`)
  - Signature: `666` bytes (`sig[0] == 0x39`)
  - Total `vchBlockSig` length: **`1,566` bytes** (`FN_DSA_512_BLOCK_SIG_ENVELOPE_LEN`)
- **`ML-DSA-44` (`scheme_id = 0x01`):**
  - Header: `500101` (`3` bytes)
  - Public key: `1,312` bytes
  - Signature: `2,420` bytes
  - Total `vchBlockSig` length: **`3,735` bytes** (`ML_DSA_44_BLOCK_SIG_ENVELOPE_LEN`)
