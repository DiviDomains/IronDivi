# DIP-PQ-3: Segregated Post-Quantum Witness, Bech32m 256-Bit Addresses & 256-Bit PQ Staking Vaults

- **DIP:** `DIP-PQ-3`
- **Track:** Track 7D Phase 3 (`P3.1` Segregated Witness Framing & Weight Accounting and `P3.2` Versioned 256-Bit PQ Output & Vault Templates)
- **Coordination Tier:** Tier C (Strict Dual-Client Consensus, Script & Wallet Lockstep)
- **Status:** Active Specification & Consensus-Inert Reference Implementation (2026-11-08)
- **Applies To:** Canonical C++ Divi Core (`DiviProject/Divi`, `divid` v3.0.0+) and Rust IronDivi (`DiviDomains/IronDivi`, `irondivid` v0.2.9+)
- **Parent Architecture Document:** [`docs/plans/post-quantum-lockstep.md`](./post-quantum-lockstep.md) (§2.2 #5–#6, §3 Tier C #3, §5 Candidate PQ Trade-Offs, §6 Phase 3 `P3.1` & `P3.2`)
- **Companion Specifications:**
  - [`docs/plans/dip-pq-0-hndl-and-crypter.md`](./dip-pq-0-hndl-and-crypter.md)
  - [`docs/plans/dip-pq-1-algorithms-and-hd.md`](./dip-pq-1-algorithms-and-hd.md)
  - [`docs/plans/dip-pq-2-hybrid-sporks.md`](./dip-pq-2-hybrid-sporks.md)

---

## 1. Abstract & Motivation

Classical Divi transaction outputs and scripts inherit two structural limitations from Bitcoin pre-SegWit script:

1. **520-Byte Script Element Ceiling (`MAX_SCRIPT_ELEMENT_SIZE = 520`):**
   Legacy `scriptSig` evaluation rejects any stack element larger than `520` bytes (`crates/divi-script/src/policy.rs:53`). Post-quantum public keys and signatures standardized in [`DIP-PQ-1`](./dip-pq-1-algorithms-and-hd.md) exceed `520` bytes by $1.2\times$–$15\times$:
   - `FN-DSA-512` (`scheme_id = 0x02`): `897 B` public key + `666 B` signature (`1,563 B` combined),
   - `ML-DSA-44` (`scheme_id = 0x01`): `1,312 B` public key + `2,420 B` signature (`3,732 B` combined),
   - `SLH-DSA-128s` (`scheme_id = 0x03`): `32 B` public key + `7,856 B` signature (`7,888 B` combined).
2. **160-Bit `Hash160` Address & Vault Commitments ($2^{80}$ Grover Preimage Bound):**
   Classical `P2PKH` (`25` bytes) and `STAKING_VAULT` (`50` bytes) scripts commit to keys via `RIPEMD160(SHA256(pk))` (`20` bytes = `160` bits), which provides $2^{80}$ post-quantum preimage resistance against Grover's search algorithm (`post-quantum-lockstep.md` §2.2 #6).

`DIP-PQ-3` resolves both constraints in lockstep across C++ `divid` and Rust `irondivid`:

1. **Segregated Post-Quantum Witness Framing (`P3.1`, §2):** Moves post-quantum public keys and signatures out of `scriptSig` into a per-input segregated witness stack (`PqWitnessStack` / `PqInputWitness`) with `MAX_PQ_WITNESS_ITEM_SIZE = 8,192 B` and `MAX_PQ_TX_WITNESS_BYTES = 16,384 B`, binds witness data via `wtxid = SHA256d(txid || witness_merkle_root)`, and accounts for witness bandwidth inside Divi's `2 MB` / `60 s` Proof-of-Stake block envelope via `weight = base_bytes * 4 + witness_bytes <= 8,000,000`.
2. **256-Bit `P2PQPKH` & `PQ_STAKING_VAULT` Output Templates (`P3.2`, §3):** Upgrades single-key outputs (`P2PQPKH`, `34` bytes) and Divi's two-tier Staking Vaults (`PQ_STAKING_VAULT`, `74` bytes) to full 32-byte `SHA-256` key commitments (`pq_address_key_hash_256` from `DIP-PQ-1` §5.5, $2^{128}$ Grover preimage resistance) while preserving `OP_REQUIRE_COINSTAKE` (`0xb9`) and cold-owner / hot-staker key separation.
3. **BIP-350 `Bech32m` (`0x2bc830a3`) Human-Readable Address Encoding (§4):** Encodes 32-byte `v1` (`P2PQPKH`) and 64-byte `v2` (`PQ_STAKING_VAULT`) witness programs across all five Divi and PrivateDivi networks (`"divi"`, `"tdivi"`, `"rdivi"`, `"pdivi"`, `"tpdivi"`).

---

## 2. Segregated Post-Quantum Witness Framing & Weight Accounting (`P3.1`)

### 2.1 Per-Input Witness Stack (`PqWitnessStack` / `PqInputWitness`)

For any transaction spending a `DIP-PQ-3` output (`P2PQPKH` or `PQ_STAKING_VAULT`), the legacy input `scriptSig` MUST be empty (`0` bytes), neutralizing legacy `scriptSig` malleability so `txid` depends strictly on outpoints, sequences, outputs, and locktime.

Each transaction input $i \in [0, |\text{vin}|)$ carries an associated `PqInputWitness` (`PqWitnessStack`) serialized in canonical Bitcoin/Divi `CompactSize` format:

```text
+-----------------------------------+---------------------------------------------------+
| CompactSize(item_count)           | item[0] .. item[item_count - 1]                   |
| 1 byte (0x00 .. 0x08)             | each: CompactSize(|item|) || item_bytes[|item|]   |
+-----------------------------------+---------------------------------------------------+
```

All `CompactSize` integers inside a `PqInputWitness` MUST be minimally encoded:
- Values `0..=252` (`0x00..=0xfc`) use `1` byte,
- Values `253..=65535` use `0xfd || u16_le` (`3` bytes; values `< 253` encoded with `0xfd` MUST be rejected as `PqWitnessError::NonCanonicalCompactSize`).

### 2.2 Consensus Witness Size Limits

Every `PqInputWitness` MUST satisfy all three bounds before script or signature evaluation:

| Constant | Value | Rationale |
|---|---|---|
| `MAX_PQ_WITNESS_STACK_ITEMS` | **`8` items** | `P2PQPKH` requires `2` items; `PQ_STAKING_VAULT` requires `3` items; `8` leaves headroom for future multi-key PQ vault extensions while preventing stack-exhaustion DoS |
| `MAX_PQ_WITNESS_ITEM_SIZE` | **`8,192` bytes** | Accommodates `SLH-DSA-128s` (`1 B` `scheme_id` + `7,856 B` signature + `1 B` `sighash_type` = `7,858 B`), `ML-DSA-44` (`2,422 B` sig item / `1,313 B` pubkey item), and `FN-DSA-512` (`668 B` sig item / `898 B` pubkey item) |
| `MAX_PQ_TX_WITNESS_BYTES` | **`16,384` bytes** | Caps total serialized witness bytes per input (`<= 16 KiB`) |

### 2.3 Canonical Witness Stack Layouts by Output Type

1. **`P2PQPKH` Input Witness (`2` items):**
   - `item[0]` (`sig_item`): `u8(scheme_id) || signature_bytes[|sig|] || u8(sighash_type)`
   - `item[1]` (`pk_item`): `u8(scheme_id) || pubkey_bytes[|pk|]`
   - Notice that `item[1]` equals `"Divi-PQ-PubKey-v1"`'s suffix `u8(scheme_id) || pubkey_bytes`, so hashing `"Divi-PQ-PubKey-v1" || item[1]` with `SHA-256` directly reproduces the 32-byte `addr_key_hash_256` committed in the `P2PQPKH` `scriptPubKey`.
2. **`PQ_STAKING_VAULT` Input Witness (`3` items):**
   - `item[0]` (`sig_item`): `u8(scheme_id) || signature_bytes[|sig|] || u8(sighash_type)`
   - `item[1]` (`pk_item`): `u8(scheme_id) || pubkey_bytes[|pk|]`
   - `item[2]` (`branch_selector`):
     - `[0x01]` (`OP_1` / truthy): selects the cold owner `OP_IF` branch (`owner_pubkey_hash_256`, which may use `ML-DSA-44`, `FN-DSA-512`, or `SLH-DSA-128s` catastrophe-recovery).
     - `[]` (`OP_0` / empty byte vector): selects the hot coinstake manager `OP_ELSE OP_REQUIRE_COINSTAKE` branch (`vault_pubkey_hash_256`).

### 2.4 Witness Merkle Root & `wtxid` (`compute_wtxid`)

For a transaction with base identifier `txid` (`32` bytes, double-SHA256 of the non-witness transaction serialization) and input witness vector `witnesses[0..N]`:

1. **Classical Identity Preservation:**
   If `witnesses` is empty or every `witnesses[i].is_empty()` is `true`, then:
   $$\text{witness\_merkle\_root} = \texttt{0x00}^{32}, \qquad \text{wtxid} = \text{txid}$$
2. **Post-Quantum Witness Commitment:**
   If at least one input has a non-empty `PqInputWitness`:
   - Each input $i \in [0, N)$ defines leaf digest:
     $$L_i = \text{SHA256}\bigl(\text{SHA256}(\text{serialize\_canonical}(\text{witnesses}[i]))\bigr)$$
   - `witness_merkle_root` (`compute_witness_merkle_root`) is the standard binary double-SHA256 Merkle root over $[L_0, \dots, L_{N-1}]$ (duplicating the trailing element at any odd-length tree layer).
   - The witness transaction identifier is:
     $$\text{wtxid} = \text{SHA256}\Bigl(\text{SHA256}\bigl(\text{txid}[32] \parallel \text{witness\_merkle\_root}[32]\bigr)\Bigr)$$

### 2.5 Witness Weight Accounting (`compute_pq_tx_weight`)

Divi enforces `MAX_BLOCK_SIZE_CURRENT = 2,000,000` bytes (`MAX_PQ_BLOCK_RAW_BYTES = 2,000,000`) on a 60-second Proof-of-Stake block target (`post-quantum-lockstep.md` §5). Because post-quantum signatures only affect transient block/mempool verification bandwidth—whereas non-witness `base_bytes` (inputs, outpoints, and UTXO-creating `scriptPubKey` outputs) permanently grow the UTXO set and chain state index—`DIP-PQ-3` prices `base_bytes` at `PQ_WITNESS_SCALE_FACTOR = 4` weight units (`WU`) per byte and `witness_bytes` at `1 WU` per byte:

$$\text{weight} = 4 \cdot \text{base\_bytes} + \text{witness\_bytes}$$

Every transaction and block MUST satisfy both limits (`validate_pq_block_weight`):
1. $\text{weight} \le \text{MAX\_PQ\_BLOCK\_WEIGHT} = 8,000,000\text{ WU}$, and
2. $\text{base\_bytes} + \text{witness\_bytes} \le \text{MAX\_PQ\_BLOCK\_RAW\_BYTES} = 2,000,000\text{ B}$.

---

## 3. Versioned 256-Bit PQ Output & Vault Script Templates (`P3.2`)

### 3.1 `P2PQPKH` (`34` Bytes, Witness Version `1`)

A standard single-key post-quantum output (`P2PQPKH`, `P2PQPKH_SCRIPT_LEN = 34`) commits to a 32-byte `DIP-PQ-1` §5.5 `pq_address_key_hash_256`:

$$\text{addr\_key\_hash\_256} = \text{SHA256}\bigl(\texttt{"Divi-PQ-PubKey-v1"} \text{ (17 B)} \parallel \text{u8}(\text{scheme\_id}) \text{ (1 B)} \parallel \text{pk\_bytes}\bigr)$$

| Byte Offset | Opcode / Value | Hex | Description |
|---|---|---|---|
| `0` | `OP_1` | `0x51` | Witness version `1` (`PQ_WITNESS_VERSION_P2PQPKH = 1`) |
| `1` | `PUSH32` | `0x20` | Direct 32-byte canonical data push |
| `2..34` | `addr_key_hash_256` | `32 B` | 256-bit `SHA-256` domain-separated PQ public-key commitment |

`is_p2pqpkh_script(&Script)` accepts a script if and only if `script.len() == 34`, `script[0] == 0x51`, and `script[1] == 0x20`. Any non-minimal push (`OP_PUSHDATA1 0x20`), wrong version opcode, or trailing byte is rejected (`None`).

### 3.2 `PQ_STAKING_VAULT` (`74` Bytes, Two-Tier 256-Bit Staking Vault)

Divi's classical `STAKING_VAULT` (`50` bytes in `crates/divi-script/src/vault.rs:87-111`) separates the cold owner key (`ownerPubKeyHash`, `20 B`) from the hot coinstake-restricted staking manager key (`vaultPubKeyHash`, `20 B`):

```text
Classical STAKING_VAULT (50 bytes):
  OP_IF (0x63) 0x14 <owner_hash160: 20B>
  OP_ELSE (0x67) OP_REQUIRE_COINSTAKE (0xb9) 0x14 <vault_hash160: 20B>
  OP_ENDIF (0x68)
  OP_OVER (0x78) OP_HASH160 (0xa9) OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
```

`DIP-PQ-3` defines `PQ_STAKING_VAULT` (`PQ_STAKING_VAULT_SCRIPT_LEN = 74` bytes) by upgrading both 20-byte `Hash160` pushes (`0x14`) to 32-byte `SHA-256` `pq_address_key_hash_256` pushes (`0x20`, `+24` bytes total) and upgrading `OP_HASH160` (`0xa9`) to 256-bit `OP_SHA256` (`0xa8`):

| Byte Offset | Opcode / Value | Hex | Description |
|---|---|---|---|
| `0` | `OP_IF` | `0x63` | Cold owner full-spend branch (`branch_selector = [0x01]`) |
| `1` | `PUSH32` | `0x20` | Direct 32-byte push for `owner_pubkey_hash_256` |
| `2..34` | `owner_pubkey_hash_256` | `32 B` | Cold owner `pq_address_key_hash_256` (e.g., `SLH-DSA-128s` or `ML-DSA-44`) |
| `34` | `OP_ELSE` | `0x67` | Hot staking manager branch (`branch_selector = []`) |
| `35` | `OP_REQUIRE_COINSTAKE` | `0xb9` | Enforces that the spending tx is a valid PoS coinstake transaction |
| `36` | `PUSH32` | `0x20` | Direct 32-byte push for `vault_pubkey_hash_256` |
| `37..69` | `vault_pubkey_hash_256` | `32 B` | Hot staking manager `pq_address_key_hash_256` (e.g., `FN-DSA-512` or `ML-DSA-44`) |
| `69` | `OP_ENDIF` | `0x68` | End of branch selection (`70` bytes through `OP_ENDIF`) |
| `70` | `OP_OVER` | `0x78` | Duplicate `[scheme_id \|\| pubkey]` above the selected 32-byte commitment |
| `71` | `OP_SHA256` | `0xa8` | Compute 256-bit `SHA-256` commitment over `"Divi-PQ-PubKey-v1" \|\| scheme_id \|\| pk` |
| `72` | `OP_EQUALVERIFY` | `0x88` | Verify the revealed PQ public key matches the branch's 32-byte commitment |
| `73` | `OP_CHECKSIG` | `0xac` | Verify the post-quantum signature under `"Divi-PQ-TxSig-v1"` |

Because `owner_pubkey_hash_256` and `vault_pubkey_hash_256` each commit to their own `scheme_id` inside `pq_address_key_hash_256(scheme_id, pubkey)`, a single `PQ_STAKING_VAULT` output natively supports **heterogeneous algorithm pairing**:
- **Hot Manager (`vault_pubkey_hash_256`):** `FN-DSA-512` (`scheme_id = 0x02`, `666 B` signature) or `ML-DSA-44` (`scheme_id = 0x01`) for fast, compact 60-second Proof-of-Stake coinstake signing.
- **Cold Owner (`owner_pubkey_hash_256`):** `SLH-DSA-128s` (`scheme_id = 0x03`, stateless `SHAKE256` hash-based signature) kept completely unrevealed behind `SHA-256` during staking, providing a zero-lattice catastrophe-recovery spend path.

### 3.3 Quantum Staking Posture Classification (`classify_staking_quantum_posture`)

`StakingQuantumPosture::from_script` (`classify_staking_script_posture` / `classify_staking_quantum_posture` in `crates/divi-script/src/vault.rs`) classifies:
- Classical `STAKING_VAULT` (`50 B`),
- Post-quantum `PQ_STAKING_VAULT` (`74 B`), and
- Post-quantum `P2PQPKH` (`34 B`)
as `StakingQuantumPosture::VaultInsulated` (`advisory_label() == "vault_only"`), while classical `P2PKH` (`25 B`) and `P2PK` outputs classify as `StakingQuantumPosture::DirectPubKeyExposed` (`advisory_label() == "mixed_or_direct_p2pkh"`).

---

## 4. BIP-350 `Bech32m` (`0x2bc830a3`) 256-Bit Address Encoding

### 4.1 Network Human-Readable Parts (`PqAddressHrp`) and Witness Versions

All `DIP-PQ-3` addresses use **BIP-350 `Bech32m`** with polymod checksum constant **`BECH32M_CONST = 0x2bc830a3`**. Legacy BIP-173 `Bech32` checksums (`0x00000001`) MUST be rejected with `PqAddressError::LegacyBech32Forbidden`.

| Network | `PqAddressHrp` Variant | HRP String | `v1` (`P2PQPKH`, `32 B` Program) Prefix | `v2` (`PQ_STAKING_VAULT`, `64 B` Program) Prefix |
|---|---|---|---|---|
| **Divi Mainnet** | `PqAddressHrp::DiviMainnet` | `"divi"` | `divi1p...` (`64` chars) | `divi1z...` (`116` chars) |
| **Divi Testnet** | `PqAddressHrp::DiviTestnet` | `"tdivi"` | `tdivi1p...` (`65` chars) | `tdivi1z...` (`117` chars) |
| **Divi Regtest** | `PqAddressHrp::DiviRegtest` | `"rdivi"` | `rdivi1p...` (`65` chars) | `rdivi1z...` (`117` chars) |
| **PrivateDivi Mainnet** | `PqAddressHrp::PrivateDiviMainnet` | `"pdivi"` | `pdivi1p...` (`65` chars) | `pdivi1z...` (`117` chars) |
| **PrivateDivi Testnet** | `PqAddressHrp::PrivateDiviTestnet` | `"tpdivi"` | `tpdivi1p...` (`66` chars) | `tpdivi1z...` (`118` chars) |

*(In the Bech32 alphabet `"qpzry9x8gf2tvdw0s3jn54khce6mua7l"`, witness version `1` maps to `'p'` and witness version `2` maps to `'z'`.)*

### 4.2 Witness Program Bijection with `scriptPubKey`

1. **Witness Version `1` (`PQ_WITNESS_VERSION_P2PQPKH = 1`):**
   - `program` is the 32-byte `addr_key_hash_256` (`52` 5-bit words).
   - Maps 1-to-1 to the 34-byte `P2PQPKH` `scriptPubKey` (`0x51 0x20 <addr_key_hash_256>`).
2. **Witness Version `2` (`PQ_WITNESS_VERSION_VAULT = 2`):**
   - `program` is the 64-byte concatenation `owner_pubkey_hash_256[32] || vault_pubkey_hash_256[32]` (`103` 5-bit words).
   - Maps 1-to-1 to the 74-byte `PQ_STAKING_VAULT` `scriptPubKey`.

---

## 5. Canonical Phase 3 Test Vectors

### Vector 1: `P2PQPKH` (`v1`, `addr_key_hash_256 = [0x11; 32]`)

- **`addr_key_hash_256` (32 B hex):**
  `1111111111111111111111111111111111111111111111111111111111111111`
- **`scriptPubKey` (34 B hex):**
  `51201111111111111111111111111111111111111111111111111111111111111111`
- **BIP-350 `Bech32m` Addresses:**
  - Divi Mainnet (`"divi"`): `divi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsvgff7j`
  - Divi Testnet (`"tdivi"`): `tdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsnfa2ee`
  - Divi Regtest (`"rdivi"`): `rdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsj9gcf6`
  - PrivateDivi Mainnet (`"pdivi"`): `pdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs2puk7m`
  - PrivateDivi Testnet (`"tpdivi"`): `tpdivi1pzyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsf68lva`

### Vector 2: `PQ_STAKING_VAULT` (`v2`, `owner = [0x22; 32]`, `vault = [0x33; 32]`)

- **`owner_pubkey_hash_256` (32 B hex):**
  `2222222222222222222222222222222222222222222222222222222222222222`
- **`vault_pubkey_hash_256` (32 B hex):**
  `3333333333333333333333333333333333333333333333333333333333333333`
- **`scriptPubKey` (74 B hex):**
  `6320222222222222222222222222222222222222222222222222222222222222222267b92033333333333333333333333333333333333333333333333333333333333333336878a888ac`
- **Divi Mainnet `Bech32m` Address (`115` chars):**
  `divi1zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3rxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvenxvc5tmafc`
