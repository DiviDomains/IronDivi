# DIP-PQ-1: Post-Quantum Signature Parameter Sets, Strict Canonical Byte Encodings, Domain Separation, and Deterministic BIP39 PQ HD Key Derivation

- **DIP:** `DIP-PQ-1`
- **Track:** Track 7C Phase 1 (`P1.2`, Prerequisite for `P1.3` Dual Crypto Libraries & Cross-FFI Fuzz Gate)
- **Coordination Tier:** Tier C (Strict Dual-Client Consensus & Wallet Lockstep)
- **Status:** Active Specification & Canonical Test Vector Suite (2026-11-07)
- **Applies To:** Canonical C++ Divi Core (`DiviProject/Divi`, `divid` v3.0.0+) and Rust IronDivi (`DiviDomains/IronDivi`, `irondivid` v0.2.9+)
- **Parent Architecture Document:** [`docs/plans/post-quantum-lockstep.md`](./post-quantum-lockstep.md) (§4 Dual-Language Consensus Bit-Parity, §5 Candidate PQ Trade-Offs, §6 Phase 1 `P1.2`)
- **Companion Specification:** [`docs/plans/dip-pq-0-hndl-and-crypter.md`](./dip-pq-0-hndl-and-crypter.md)

---

## 1. Abstract & Dual-Client Consensus Parity Mandate

The single highest consensus risk in a dual-client (`C++11` `divid` + `Rust` `irondivid`) post-quantum upgrade is a **verification edge-case divergence**: if one client's verifier accepts a non-canonical hint vector, an unreduced polynomial coefficient ($\ge q$), a borderline $L_2$ signature norm, or a trailing byte that the other client rejects, an attacker can craft a single transaction or Proof-of-Stake block that splits mainnet between `divid` and `irondivid`.

`DIP-PQ-1` fixes the exact mathematical and byte-level rules for all post-quantum signature schemes across the Divi ecosystem:

1. **Exact NIST Parameter Sets (§2):** Fixes four scheme identifiers (`scheme_id` `0x01`–`0x04`) corresponding to `ML-DSA-44` (NIST FIPS 204), `FN-DSA-512` (NIST FIPS 206 / Falcon-512), `SLH-DSA-128s` (NIST FIPS 205), and `LMS-SHA256-M32-H10` with `LMOTS-SHA256-N32-W4` (NIST SP 800-208 / RFC 8554).
2. **Strict Canonical Byte Encodings & Consensus Rejection Rules (§3):** Prohibits floating-point arithmetic in consensus verification and defines deterministic, bit-exact canonical checks rejecting out-of-range coefficients ($\ge q$), non-monotonic or over-budget `ML-DSA-44` hint indices, non-canonical `FN-DSA-512` Golomb-Rice `-0` sign encodings, and any leading/trailing padding bytes.
3. **Explicit Domain-Separation Tags & Message Prehashing (§4):** Binds every post-quantum signature to its exact protocol role (`"Divi-PQ-TxSig-v1"`, `"Divi-PQ-BlockSig-v1"`, `"Divi-PQ-Spork-v1"`), network magic (`4` bytes), and `scheme_id` (`1` byte), preventing cross-context signature replay between transactions, block headers, and Sporks, as well as cross-network replay between Divi Mainnet, Testnet, Regtest, and PrivateDivi.
4. **Deterministic BIP39 Post-Quantum HD Key Derivation (§5):** Defines a purely hash-based, elliptic-curve-free hardened derivation tree rooted at the user's existing 512-bit BIP39 seed (`HMAC-SHA512("Divi PQ seed v1", bip39_seed)` $\to$ `m / 44' / coin_type' / account' / scheme' / index'` $\to$ `SHAKE256` DRBG keygen seed) so any existing 24-word mnemonic deterministically restores byte-for-byte identical post-quantum keys and addresses in both C++ `divid` and Rust `irondivid`.

---

## 2. Exact NIST Post-Quantum Signature Parameter Sets

Every post-quantum public key and signature in Divi consensus or governance carries a 1-byte `scheme_id` prefix identifying its exact parameter set. No dynamic parameter negotiation or variable-length parameter sets are permitted inside a given `scheme_id`:

| `scheme_id` | Algorithm Identifier | Standard | Security Category | Public Key Bytes (`\|pk\|`) | Signature Bytes (`\|sig\|`) | Keygen Seed Bytes | Protocol Role |
|---|---|---|---|---|---|---|---|
| `0x01` | **`ML-DSA-44`** | NIST FIPS 204 (Final) | Category 2 (Module-LWE / Module-SIS, $q = 8380417$, $(k, \ell) = (4, 4)$) | `1,312 B` | `2,420 B` | `32 B` ($\xi$) | Primary pure-integer lattice transaction witness (`DIP-PQ-3`) & Spork/Block fallback |
| `0x02` | **`FN-DSA-512`** | NIST FIPS 206 (Falcon-512) | Category 1 (NTRU lattice over $\mathbb{Z}_q[x]/(x^{512}+1)$, $q = 12289$) | `897 B` | `666 B` (padded) | `64 B` (`SHAKE256` seed) | Compact PoS `vchBlockSig` (`DIP-PQ-4`) & high-throughput transaction witness (`DIP-PQ-3`) |
| `0x03` | **`SLH-DSA-128s`** | NIST FIPS 205 (`SLH-DSA-SHAKE-128s`) | Category 1 (Stateless hash-based, `SHAKE256`, $n=16, h=63, d=7, a=12, k=14, w=16$) | `32 B` | `7,856 B` | `48 B` (`SK.seed \|\| SK.prf \|\| PK.seed`) | Cold-vault catastrophe-recovery spend leaf (`PQ_STAKING_VAULT` owner recovery without lattice assumptions) |
| `0x04` | **`LMS-SHA256-M32-H10`** | NIST SP 800-208 / RFC 8554 (`LMS_SHA256_M32_H10` + `LMOTS_SHA256_N32_W4`) | Category 5 ($2^{128}$ Grover SHA-256 preimage, tree height $H=10$, $1,024$ leaves, Winternitz $w=4$, $p=67$) | `60 B` | `2,512 B` | `64 B` (`I[16 B] \|\| SEED[32 B] \|\| aux[16 B]`) | **Spork governance authority (`strSporkKey` in `DIP-PQ-2`) only** — never permitted in transaction scripts or block headers |

### 2.1 Fixed Mathematical Constants per Scheme

1. **`ML-DSA-44` (`scheme_id = 0x01`, FIPS 204 Table 1):**
   - Ring: $R_q = \mathbb{Z}_q[X]/(X^{256} + 1)$ with prime modulus $q = 8380417 = 2^{23} - 2^{13} + 1$.
   - Dimensions: $(k, \ell) = (4, 4)$, dropped bits $d = 13$, challenge weight $\tau = 39$, commitment range $\gamma_1 = 2^{17} = 131072$, low-order rounding range $\gamma_2 = (q - 1)/88 = 95232$, secret coefficient bound $\eta = 2$, $\beta = \tau \cdot \eta = 78$, maximum hint ones $\omega = 80$, collision strength $\lambda = 128$ bits ($\tilde{c} \in \{0,1\}^{256}$, `32` bytes).
   - Secret key size (`sk`): `2,560` bytes (`rho[32] || K[32] || tr[64] || s1[4*96] || s2[4*96] || t0[4*416]`).

2. **`FN-DSA-512` (`scheme_id = 0x02`, FIPS 206 / Falcon-512):**
   - Ring: $\mathbb{Z}_q[X]/(X^{512} + 1)$ with prime modulus $q = 12289 = 3 \cdot 2^{12} + 1$ ($\log_2 n = 9$, $n = 512$).
   - Maximum squared Euclidean norm bound: $\lfloor \beta^2 \rfloor = 34034726$ (`0x020753A6`).
   - Public key size: `897` bytes (`1` header byte `0x09` + `896` bytes of 512 packed 14-bit unsigned coefficients $h_i \in [0, 12288]$).
   - Signature size: fixed padded format of **exactly `666` bytes** (`1` header byte `0x39` + `40` bytes nonce $r$ + `625` bytes compressed $s_2$ payload with zero-padding to byte `666`). Variable-length unpadded Falcon signatures MUST be rejected in consensus.

3. **`SLH-DSA-128s` (`scheme_id = 0x03`, FIPS 205 Table 2 `SLH-DSA-SHAKE-128s`):**
   - Hash function instantiation: `SHAKE256` (pure Keccak-f[1600], sharing the exact same permutation already required by `ML-DSA-44` and `FN-DSA-512`).
   - Parameters: $n = 16$ bytes, total tree height $h = 63$, hypertree layers $d = 7$ ($h' = 9$), FORS trees $k = 14$ of height $a = 12$, Winternitz parameter $w = 16$ ($\mathit{len} = 35$).
   - Sizes: `|pk| = 2n = 32` bytes (`PK.seed[16] || PK.root[16]`), `|sk| = 4n = 64` bytes, `|sig| = 7,856` bytes.

4. **`LMS-SHA256-M32-H10` (`scheme_id = 0x04`, NIST SP 800-208 / RFC 8554):**
   - LMS typecode: `LMS_SHA256_M32_H10 = 0x00000006` (big-endian `u32`, $m = 32$ bytes, tree height $H = 10$, $2^{10} = 1,024$ one-time signatures per key).
   - LMOTS typecode: `LMOTS_SHA256_N32_W4 = 0x00000003` (big-endian `u32`, $n = 32$ bytes, $w = 4$, $p = 67$, $ls = 4$).
   - Public key size: **exactly `60` bytes**:
     `u32be(0x00000006) [4 B] || u32be(0x00000003) [4 B] || I [16 B] || T[1] [32 B] || reserved_zero [4 B = 0x00000000]`
     *(Note: RFC 8554 `lms_public_key` is `56` bytes; `DIP-PQ-1` appends a mandatory 4-byte `u32be(0x00000000)` key-epoch / version tag to align the Spork public key commitment to `60` bytes as specified in `post-quantum-lockstep.md` §5. Any non-zero byte in bytes `56..60` MUST be rejected.)*
   - Signature size: **exactly `2,512` bytes**:
     `u32be(q) [4 B] || lmots_signature [4 + 32 + 67*32 = 2,180 B] || u32be(0x00000006) [4 B] || path[10 * 32 = 320 B] || reserved_zero [4 B = 0x00000000]`.

---

## 3. Strict Canonical Byte Encodings & Consensus Verification Invariants

Both `divid` (`divi/src/pqcrypto/`) and `irondivid` (`crates/divi-crypto/src/pq/`) MUST enforce the following verification invariants with **zero floating-point instructions** (no `float`/`double`/`f32`/`f64` in any consensus verification path):

### 3.1 Global Length & Prefix Rules (All Schemes)

1. **Exact Length Check Before Parsing:**
   Before allocating or unpacking any polynomial or hash tree, the verifier MUST check that `pubkey.len() == expected_pk_len(scheme_id)` and `sig.len() == expected_sig_len(scheme_id)`. Any short or oversized input (including a single trailing `0x00` byte) MUST immediately return `false` (`ScriptError::BadSignature` / `ConsensusError::InvalidPqSignature`).
2. **Role Restriction Check:**
   - `scheme_id == 0x04` (`LMS-SHA256-M32-H10`) is valid **only** when `domain_tag == "Divi-PQ-Spork-v1"`. Any transaction witness or block signature presenting `scheme_id == 0x04` MUST be rejected unconditionally.
   - `scheme_id == 0x03` (`SLH-DSA-128s`) is valid in `"Divi-PQ-TxSig-v1"` (`P2PQPKH` and `PQ_STAKING_VAULT` cold owner recovery branch) and `"Divi-PQ-Spork-v1"`, and MUST be rejected in `"Divi-PQ-BlockSig-v1"` (`vchBlockSig` requires sub-millisecond verification via `0x01` `ML-DSA-44` or `0x02` `FN-DSA-512`).

### 3.2 `ML-DSA-44` (`0x01`) Canonical Verification Checks (FIPS 204 Algorithm 3 + 8)

1. **Public Key `pk` (`1,312` bytes = `rho[32] || t1_packed[1280]`):**
   - `t1` consists of $k = 4$ polynomials of 256 coefficients, each encoded in $23 - d = 10$ bits ($4 \times 256 \times 10 / 8 = 1,280$ bytes). Every 10-bit coefficient lies in $[0, 1023] < 2^{10}$, which is bijective and has no out-of-range encoding.
2. **Signature `sig` (`2,420` bytes = `c_tilde[32] || z_packed[2304] || h_packed[84]`):**
   - **`z` Unpacking (`BitUnpack` with $\gamma_1 = 2^{17}$):** Each of the $\ell = 4$ polynomials has 256 coefficients packed at 18 bits each ($4 \times 256 \times 18 / 8 = 2,304$ bytes). Every unpacked coefficient $z_{i,j} = \gamma_1 - u_{i,j}$ MUST satisfy:
     $$\|z\|_\infty < \gamma_1 - \beta = 131072 - 78 = 130994$$
     If any coefficient satisfies $|z_{i,j}| \ge 130994$ (including the asymmetrical boundary $z_{i,j} = -\gamma_1 = -131072$), verification MUST fail immediately.
   - **Hint Vector `h` (`HintBitUnpack`, `84` bytes = $\omega + k = 80 + 4$):**
     Let `h_bytes = sig[2336..2420]`, where `offsets = h_bytes[80..84]` are the cumulative 1-counts for polynomials $i \in \{0, 1, 2, 3\}$:
     1. **Monotonicity & Bound:** Must satisfy $0 \le \text{offsets}[0] \le \text{offsets}[1] \le \text{offsets}[2] \le \text{offsets}[3] \le \omega = 80$.
     2. **Strictly Increasing Indices per Polynomial:** For each polynomial $i \in \{0, 1, 2, 3\}$, with slice $s_i = \text{h\_bytes}[\text{start}_i .. \text{offsets}[i]]$ (where $\text{start}_0 = 0$ and $\text{start}_i = \text{offsets}[i-1]$): for every $j$ with $\text{start}_i < j < \text{offsets}[i]$, MUST satisfy $\text{h\_bytes}[j-1] < \text{h\_bytes}[j]$ (strictly ascending; duplicate or out-of-order indices MUST fail).
     3. **Zero Padding in Unused Hint Slots:** For every index $j \in [\text{offsets}[3], 80)$, MUST satisfy $\text{h\_bytes}[j] == 0$. Any non-zero byte in the unused tail of the 80-byte hint index array MUST fail verification.
     4. **Hint Weight Check:** Total number of 1s in $h$ equals $\text{offsets}[3] \le 80$.
   - **FIPS 204 Pure Mode (` ML-DSA.Verify ` with empty context `ctx = ""`):**
     The message $M'$ passed to internal `ML-DSA.Verify_internal` is `0x00 || 0x00 || prehash_msg` (`2 + 64 = 66` bytes), where `prehash_msg` is the 64-byte domain-separated digest defined in §4.

### 3.3 `FN-DSA-512` (`0x02`) Canonical Verification Checks (FIPS 206 / Falcon-512)

1. **Public Key `pk` (`897` bytes):**
   - Byte `0` MUST equal `0x09` ($0000\,1001_2$, indicating $\log_2 n = 9$).
   - Bytes `1..897` (`896` bytes = $512 \times 14$ bits) unpack into 512 unsigned 14-bit integers $h_i$ (big-endian bit stream).
   - **Strict Coefficient Range Check:** Every $h_i$ ($0 \le i < 512$) MUST satisfy $h_i < q = 12289$. If any $h_i \in [12289, 16383]$, verification MUST fail before NTT conversion.
2. **Signature `sig` (`666` bytes):**
   - Byte `0` MUST equal `0x39` ($0011\,1001_2$: fixed padded compressed format `0011` with $\log_2 n = 9$). Any other header byte (such as `0x29` variable-length or `0x59` uncompressed) MUST be rejected.
   - Bytes `1..41` (`40` bytes) are the salt/nonce $r$.
   - Bytes `41..666` (`625` bytes = `5,000` bits) encode the compressed polynomial $s_2 = (s_{2,0}, \dots, s_{2,511})$:
     1. For each coefficient $i \in [0, 511]$:
        - Read 1 sign bit $b_{\text{sign}}$, then 7 low bits $u_{\text{low}} \in [0, 127]$, then unary high bits (count of `0` bits before a terminating `1` bit) $u_{\text{high}}$ so $|s_{2,i}| = u_{\text{low}} + 128 \cdot u_{\text{high}}$.
        - **Canonical Zero Rule (Reject `-0`):** If $|s_{2,i}| == 0$ and $b_{\text{sign}} == 1$, verification MUST fail immediately.
        - **Range Bound:** If $|s_{2,i}| > 2047$, verification MUST fail immediately.
     2. **Zero Padding After Coefficient 511:** Every remaining bit in bytes `41..666` after the terminating `1` bit of $s_{2,511}$ up to bit `5,000` MUST be `0`. Any `1` bit in the trailing padding MUST fail verification.
3. **Pure Integer Norm & NTT Verification:**
   - Compute $c = \text{HashToPoint}(r \parallel \text{prehash\_msg}, q=12289, n=512)$ via `SHAKE256` rejection sampling (`u16 < 61445`).
   - Compute $s_1 = c - s_2 \cdot h \pmod{12289}$ in $\mathbb{Z}_{12289}[X]/(X^{512}+1)$ using `u16`/`u32` NTT arithmetic with centered reduction into $[-(q-1)/2, +(q-1)/2] = [-6144, +6144]$.
   - Compute exact 64-bit unsigned integer squared norm:
     $$N = \sum_{i=0}^{511} \left(\text{ int64 }(s_{1,i})^2 + \text{ int64 }(s_{2,i})^2\right)$$
   - Verification succeeds if and only if $N \le 34034726$.

### 3.4 `SLH-DSA-128s` (`0x03`) Canonical Verification Checks (FIPS 205)

1. **`pk` (`32` bytes) and `sig` (`7,856` bytes):**
   - `pk` is `PK.seed[16] || PK.root[16]`; `sig` is `R[16] || SIG_FORS[14 * 13 * 16 = 2,912 B] || SIG_HT[7 * (35 + 9) * 16 = 4,928 B]`. Every 16-byte hash node is unconstrained in $\{0,1\}^{128}$, so any 7,856-byte signature has a unique parse; verification succeeds if and only if `SLH-DSA.Verify(pk, prehash_msg, sig, ctx="")` recomputes `PK.root` in constant time.

### 3.5 `LMS-SHA256-M32-H10` (`0x04`) Canonical Verification Checks (SP 800-208 / RFC 8554)

1. **Public Key `pk` (`60` bytes):**
   - `pk[0..4]` MUST equal `0x00000006` (`LMS_SHA256_M32_H10`).
   - `pk[4..8]` MUST equal `0x00000003` (`LMOTS_SHA256_N32_W4`).
   - `pk[56..60]` MUST equal `0x00000000`.
2. **Signature `sig` (`2,512` bytes):**
   - Leaf index $q = \text{u32be}(\text{sig}[0..4])$ MUST satisfy $0 \le q < 2^{10} = 1024$.
   - `sig[4..8]` (LMOTS typecode) MUST equal `0x00000003`.
   - `sig[2184..2188]` (LMS typecode) MUST equal `0x00000006`.
   - `sig[2508..2512]` MUST equal `0x00000000`.
   - Recompute LMOTS public key candidate $K_c$ from `(I, q, C, y[0..67], prehash_msg)` and walk the 10-level Merkle path `sig[2188..2508]`; accept if and only if the root equals `pk[24..56]`.

---

## 4. Explicit Domain-Separation Tags & Message Prehashing

Every post-quantum signature in Divi signs a 64-byte (`512`-bit) domain-separated message digest `prehash_msg` constructed with `SHA-512`. No raw un-tagged message is ever passed to a post-quantum signer or verifier.

### 4.1 Canonical Domain-Separation Tags

| Tag Constant (ASCII bytes, no NUL terminator) | Length | Context Payload (`ctx_payload`) | Used By |
|---|---|---|---|
| **`"Divi-PQ-TxSig-v1"`** (`446976692d50512d54785369672d7631`) | `16 B` | `sighash_u256 (32 B)` (DIP-PQ-3 transaction witness sighash) | Transaction input witnesses (`P2PQPKH`, `PQ_STAKING_VAULT`) |
| **`"Divi-PQ-BlockSig-v1"`** (`446976692d50512d426c6f636b5369672d7631`) | `19 B` | `block_header_hash_u256 (32 B) \|\| coinstake_wtxid_u256 (32 B)` (`64 B`) | Proof-of-Stake `vchBlockSig` (`DIP-PQ-4`) |
| **`"Divi-PQ-Spork-v1"`** (`446976692d50512d53706f726b2d7631`) | `16 B` | `nSporkID (i32 LE, 4 B) \|\| nValue (i64 LE, 8 B) \|\| nTimeSigned (i64 LE, 8 B)` (`20 B`) | Network Spork governance messages (`CSporkMessage` v2 in `DIP-PQ-2`) |

### 4.2 Exact 64-Byte `prehash_msg` Construction

Given:
- `domain_tag`: one of the three ASCII byte strings in §4.1,
- `network_magic`: the 4-byte wire magic of the active chain (`[0xdf, 0xf0, 0xc8, 0xf3]` on Divi Mainnet, `[0xf4, 0xc4, 0xd7, 0xaa]` on Divi Testnet, `[0xf1, 0xdd, 0x76, 0xef]` on Divi Regtest, `[0xb7, 0xdc, 0x62, 0x4e]` on PrivateDivi Mainnet),
- `scheme_id`: 1-byte unsigned integer (`0x01`, `0x02`, `0x03`, or `0x04`),
- `pk_hash256`: `SHA-256(scheme_id || pk_bytes)` (`32` bytes, binding the signer's exact public key and scheme to the message digest to prevent multi-key / key-substitution attacks),
- `ctx_payload`: the context payload defined in §4.1:

$$\text{prehash\_msg} = \text{SHA512}\Bigl(\text{u8}(\lvert\text{domain\_tag}\rvert) \parallel \text{domain\_tag} \parallel \text{network\_magic (4 B)} \parallel \text{scheme\_id (1 B)} \parallel \text{pk\_hash256 (32 B)} \parallel \text{ctx\_payload}\Bigr)$$

The resulting 64-byte `prehash_msg` is passed as the message input `M` to `ML-DSA-44`, `FN-DSA-512`, `SLH-DSA-128s`, or `LMS-SHA256-M32-H10`.

---

## 5. Deterministic BIP39 Post-Quantum HD Key Derivation

A core lockstep requirement of `post-quantum-lockstep.md` (§3 Tier C #1, §4.2 #3, §6 `P1.2`) is that **a user's existing 24-word BIP39 mnemonic + optional passphrase deterministically restores the exact same post-quantum keys and addresses in both C++ `divid` and Rust `irondivid`**, without requiring the user to back up a second mnemonic phrase.

### 5.1 Root Domain Separation from Classical BIP32 (`"Divi PQ seed v1"`)

Classical BIP32 derives the secp256k1 master node via `HMAC-SHA512(Key = "Bitcoin seed", Data = bip39_seed)`. To guarantee complete cryptographic isolation between the classical secp256k1 tree and the post-quantum tree (so compromising any classical `xpub` or `secp256k1` key reveals zero bits about the PQ master node), the post-quantum HD master node is derived from the 64-byte (`512`-bit) BIP39 seed using the domain key **`"Divi PQ seed v1"`** (`15` ASCII bytes: `446976692050512073656564207631`):

$$I_{\text{master}} = \text{HMAC-SHA512}\bigl(\text{Key} = \texttt{"Divi PQ seed v1"},\ \text{Data} = \text{bip39\_seed (64 B)}\bigr)$$

$$k_{\text{master}} = I_{\text{master}}[0..32] \text{ (32 B)}, \quad c_{\text{master}} = I_{\text{master}}[32..64] \text{ (32 B)}$$

### 5.2 Hardened PRF Child Key Derivation (`CKDpriv_PQ`)

Post-quantum schemes do not have an elliptic-curve group homomorphism and therefore **never support non-hardened (`xpub`) child derivation**. Every level of the post-quantum HD path MUST be hardened ($i \ge 2^{31} = \texttt{0x80000000}$). Any call attempting non-hardened derivation ($i < \texttt{0x80000000}$) MUST return an error (`HdError::NonHardenedPqDerivationForbidden`).

Given parent node $(k_{\text{par}}, c_{\text{par}}) \in \{0,1\}^{256} \times \{0,1\}^{256}$ and hardened child index $i = \texttt{0x80000000} \mid \text{index}$ ($\text{index} \in [0, 2^{31}-1]$):

$$I = \text{HMAC-SHA512}\bigl(\text{Key} = c_{\text{par}},\ \text{Data} = \texttt{0x00} \parallel k_{\text{par}} \text{ (32 B)} \parallel \text{u32be}(i) \text{ (4 B)}\bigr)$$

$$k_{\text{child}} = I[0..32] \text{ (32 B)}, \quad c_{\text{child}} = I[32..64] \text{ (32 B)}$$

Notice that this step depends **only** on `HMAC-SHA512` (no `secp256k1` scalar addition modulo $n$ and no curve point multiplication), so every node $(k, c)$ has uniform 256-bit entropy and zero failure states.

### 5.3 Canonical 5-Level Derivation Path (`m / 44' / coin_type' / account' / scheme' / index'`)

All post-quantum wallet keys are derived at the 5-level hardened path:

$$\texttt{m / 44' / coin\_type' / account' / scheme' / index'}$$

where:
1. **Purpose (`44'` = `0x8000002C`):** Preserves unified BIP44 account numbering with the user's classical wallet.
2. **Coin Type (`coin_type'`):** Matches [`docs/divid-differences.md`](../divid-differences.md) `W5`:
   - `301'` (`0x8000012D`) on **Divi Mainnet**
   - `1'` (`0x80000001`) on **Divi Testnet & Regtest** (and PrivateDivi Testnet/Regtest)
   - `801'` (`0x80000321`) on **PrivateDivi Mainnet**
3. **Account (`account'` = `0x80000000 | account`):**
   - `0'` (`0x80000000`): Default spend & receiving account
   - `1'` (`0x80000001`): Internal change account
   - `2'` (`0x80000002`): Cold Staking Vault Owner (`ownerKeyHash256`) account
   - `3'` (`0x80000003`): Hot Staking Vault Manager (`vaultKeyHash256`) account
4. **Scheme (`scheme'` = `0x80000000 | u32(scheme_id)`):**
   - `1'` (`0x80000001`): `ML-DSA-44` (`scheme_id = 0x01`)
   - `2'` (`0x80000002`): `FN-DSA-512` (`scheme_id = 0x02`)
   - `3'` (`0x80000003`): `SLH-DSA-128s` (`scheme_id = 0x03`)
   - `4'` (`0x80000004`): `LMS-SHA256-M32-H10` (`scheme_id = 0x04`, Spork authority tooling only)
5. **Address Index (`index'` = `0x80000000 | index`):** Sequential hardened key index $0', 1', 2', \dots$.

### 5.4 Leaf Node to Algorithm Keygen Seed (`SHAKE256` DRBG Expansion)

From the leaf node $(k_{\text{leaf}}, c_{\text{leaf}})$ at `m / 44' / coin_type' / account' / scheme' / index'`, both `divid` and `irondivid` derive an arbitrary-length deterministic keygen byte stream via `SHAKE256` (FIPS 202) with the 17-byte ASCII prefix **`"Divi-PQ-Keygen-v1"`** (`446976692d50512d4b657967656e2d7631`):

$$\text{KeygenStream} = \text{SHAKE256}\bigl(\texttt{"Divi-PQ-Keygen-v1"} \text{ (17 B)} \parallel \text{u8}(\text{scheme\_id}) \text{ (1 B)} \parallel k_{\text{leaf}} \text{ (32 B)} \parallel c_{\text{leaf}} \text{ (32 B)}\bigr)$$

Each algorithm consumes its exact required seed slice from the start of `KeygenStream`:
- **`ML-DSA-44` (`0x01`):** `xi = KeygenStream[0..32]` (`32` bytes), passed directly to FIPS 204 `ML-DSA.KeyGen_internal(xi)`.
- **`FN-DSA-512` (`0x02`):** `seed = KeygenStream[0..64]` (`64` bytes), initializing the FIPS 206 / Falcon reference `SHAKE256` PRNG for `keygen`.
- **`SLH-DSA-128s` (`0x03`):** `SK.seed = KeygenStream[0..16]`, `SK.prf = KeygenStream[16..32]`, `PK.seed = KeygenStream[32..48]` (`48` bytes total), passed directly to FIPS 205 `SLH-DSA.KeyGen_internal(SK.seed, SK.prf, PK.seed)`.
- **`LMS-SHA256-M32-H10` (`0x04`):** `I = KeygenStream[0..16]` (`16`-byte tree identifier) and `SEED = KeygenStream[16..48]` (`32`-byte master LMOTS secret seed per SP 800-208 Appendix A).

### 5.5 256-Bit Post-Quantum Key Commitment (`PQKeyHash256`)

To preserve $2^{128}$ post-quantum preimage resistance against Grover's algorithm (`post-quantum-lockstep.md` §2.2 #6 & §6 `P3.2`), post-quantum scripts and addresses commit to the full 32-byte `SHA-256` digest of the domain-prefixed public key rather than 160-bit `RIPEMD160(SHA256(pk))`:

$$\text{PQKeyHash256}(\text{scheme\_id}, \text{pk}) = \text{SHA256}\bigl(\texttt{"Divi-PQ-PubKey-v1"} \text{ (17 B)} \parallel \text{u8}(\text{scheme\_id}) \text{ (1 B)} \parallel \text{pk}\bigr) \quad (\text{32 bytes})$$

---

## 6. Canonical Phase 1 Test Vectors (`tests/vectors/pq/dip_pq_1_vectors.json`)

Both C++ `divid` (`divi/src/test/pqcrypto_tests.cpp`) and Rust `irondivid` (`crates/divi-crypto/tests/pq_vectors.rs` & `crates/divi-wallet/src/hd.rs`) MUST produce bit-identical outputs on the following canonical test vectors:

### Vector 1: BIP39 Seed to Master PQ Node (`"Divi PQ seed v1"`)

- **Mnemonic (24 words):**
  `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art`
- **Passphrase:** `""` (empty string)
- **BIP39 64-Byte Seed (hex):**
  ```text
  408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840
  ```
- **Master PQ Node (`HMAC-SHA512("Divi PQ seed v1", bip39_seed)`):**
  - `k_master` (`I[0..32]`):
    ```text
    47cd0fc16effbec1c630f59b2f3aae6924a13d6058d7fab33395829e21fe7a37
    ```
  - `c_master` (`I[32..64]`):
    ```text
    80b033237fd0594e16a0b3afaa608abbdf86f03cff7bf4c2ca248fbf95f9a77a
    ```

### Vector 2: Divi Mainnet (`coin_type = 301'`) Leaf Keys & `SHAKE256` Keygen Seeds

1. **`ML-DSA-44` (`scheme_id = 0x01`) at `m / 44' / 301' / 0' / 1' / 0'`:**
   - `k_leaf`: `eb2660d9798dde6a7dfd99da787fdcc470b3a19270fa04a708986c282904b8a8`
   - `c_leaf`: `abce2677b924f115d859de017055629b07357fcd1d6772e4dc7dd6bddf3e1e9e`
   - `xi = KeygenStream[0..32]` (`32` B):
     ```text
     5453ad6e329dfd732cffdd3f9adaa808682f8c6597100bb7912b03116c26f38a
     ```
   - `KeygenStream[0..64]` (`64` B):
     ```text
     5453ad6e329dfd732cffdd3f9adaa808682f8c6597100bb7912b03116c26f38a20a2a8f18860a1ae440eae38b21af9a36ae65680f430fe5b4684a4e68a9ef9a1
     ```

2. **`FN-DSA-512` (`scheme_id = 0x02`) at `m / 44' / 301' / 0' / 2' / 0'`:**
   - `k_leaf`: `59d356d84afc5b11ec409c8485c8c4cc63f85e7035a25d36fcf19cbec285f8f2`
   - `c_leaf`: `951f0c084b45664df19555b13fbbc391f0af07fb27d403db2a2b65de85d3dd97`
   - `seed = KeygenStream[0..64]` (`64` B):
     ```text
     61644f3db169e2dd7a7750f58c032b525fdf6d8afbc0a3243ac01606ace6d5ae2d2865aba8d5f1cf73d359389b5a28a92e279794c3bcad50405d743b7a83ee67
     ```

3. **`SLH-DSA-128s` (`scheme_id = 0x03`) at `m / 44' / 301' / 0' / 3' / 0'`:**
   - `k_leaf`: `6ef5a0ac7cf91103ade416d58fa8c26887bd0c489757aeb3cff9e40acd8af5af`
   - `c_leaf`: `18c4307336d7e9cad796e51355c38692fca7a4cc7bd8d230fd2b032f28ed34b3`
   - `SK.seed || SK.prf || PK.seed = KeygenStream[0..48]` (`48` B):
     ```text
     1c9107b4294ea04d121061281585ea22b78f0dddc6c4dc588448f2eee2287c70f11b6af4d424344c4522942c3123320a
     ```

4. **`LMS-SHA256-M32-H10` (`scheme_id = 0x04`) at `m / 44' / 301' / 0' / 4' / 0'`:**
   - `k_leaf`: `40454acf8491c7e178e9417993e1b48fc1b9cbe703569c9515cf783d4e57721c`
   - `c_leaf`: `0c175a7c66ac8f3d6bd514f4eef0daa0f70b59aab0ce8ee599c8f67b7923b3c9`
   - `I (16 B) = KeygenStream[0..16]`: `bf2fd2b1a59e04f9b9da4243bb4b78d6`
   - `SEED (32 B) = KeygenStream[16..48]`: `4d4fc0255e0916ff0fc4e1ebcf26d65b45cc4c47717afc7cecb68799b5c3d981`

### Vector 3: Cross-Network Coin-Type Isolation (`1'` Testnet/Regtest & `801'` PrivateDivi Mainnet)

1. **Testnet / Regtest `ML-DSA-44` (`m / 44' / 1' / 0' / 1' / 0'`):**
   - `k_leaf`: `279ea392e7ca0264cfcc9e78568e9cfaaa8e402ae0b42151bbd1a659105ea819`
   - `c_leaf`: `92a323683917ed6642ed3398404b179e69e239d28287b81617d17406db588b71`
   - `xi = KeygenStream[0..32]` (`32` B):
     ```text
     866b3335fad05491e55b4c8b95dc87a249d01beb8d6d6bd190eb6e2836d1def2
     ```

2. **PrivateDivi Mainnet `ML-DSA-44` (`m / 44' / 801' / 0' / 1' / 0'`):**
   - `k_leaf`: `1d61da22286da2de751a8e2bc126a3bc79606a194e68ac23507814d95888760d`
   - `c_leaf`: `69966d43af748806b5dfe98a925dbf06562d9a8dec2f44be446493ce4994eb7a`
   - `xi = KeygenStream[0..32]` (`32` B):
     ```text
     a1eba3460aeb33c7c46ebf4957cab8761fd8e5f305141d1e8617657655ad9206
     ```

### Vector 4: Domain-Separated `prehash_msg` Construction

1. **Transaction Witness Domain (`"Divi-PQ-TxSig-v1"`, `scheme_id = 0x01` `ML-DSA-44`):**
   - `domain_tag`: `"Divi-PQ-TxSig-v1"` (`16` bytes, length byte `0x10`)
   - `network_magic`: `[0xdf, 0xf0, 0xc8, 0xf3]` (Divi Mainnet)
   - `scheme_id`: `0x01` (`ML-DSA-44`)
   - `pk_hash256`: `32` bytes of `0xaa` (`aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`)
   - `ctx_payload` (`sighash_u256`): `32` bytes of `0xbb` (`bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`)
   - **Serialized Preimage (`86` bytes hex):**
     ```text
     10446976692d50512d54785369672d7631dff0c8f301aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
     ```
   - **Resulting 64-Byte `prehash_msg = SHA-512(preimage)` (hex):**
     ```text
     35a53a5300c86e71a0ca916cbbb5000fa2f06dca1b6bd6938a0945c92d00c9dcef28976fbd763b535da1683a0ca12e0cf65592666751bb2eb4bf97bf1201132f
     ```

2. **Proof-of-Stake Block Header Domain (`"Divi-PQ-BlockSig-v1"`, `scheme_id = 0x02` `FN-DSA-512`):**
   - `domain_tag`: `"Divi-PQ-BlockSig-v1"` (`19` bytes, length byte `0x13`)
   - `network_magic`: `[0xdf, 0xf0, 0xc8, 0xf3]` (Divi Mainnet)
   - `scheme_id`: `0x02` (`FN-DSA-512`)
   - `pk_hash256`: `32` bytes of `0xaa`
   - `ctx_payload` (`block_header_hash_u256 || coinstake_wtxid_u256`): `32` bytes of `0xcc` followed by `32` bytes of `0xdd` (`64` bytes)
   - **Serialized Preimage (`121` bytes hex):**
     ```text
     13446976692d50512d426c6f636b5369672d7631dff0c8f302aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
     ```
   - **Resulting 64-Byte `prehash_msg = SHA-512(preimage)` (hex):**
     ```text
     c87bc21802e2ceaba45c471cf9d4911b808223789d053b77e096378e6d2b85483af8e1b04a9022e10f336ab571205852de60ac31f965af19c52312380ec8ab9c
     ```

3. **Network Spork Governance Domain (`"Divi-PQ-Spork-v1"`, `scheme_id = 0x04` `LMS-SHA256-M32-H10`):**
   - `domain_tag`: `"Divi-PQ-Spork-v1"` (`16` bytes, length byte `0x10`)
   - `network_magic`: `[0xdf, 0xf0, 0xc8, 0xf3]` (Divi Mainnet)
   - `scheme_id`: `0x04` (`LMS-SHA256-M32-H10`)
   - `pk_hash256`: `32` bytes of `0xaa`
   - `ctx_payload`: `nSporkID = 10012` (`1c270000` LE), `nValue = 4070908800` (`8023a5f200000000` LE), `nTimeSigned = 1700000000` (`00f1536500000000` LE) (`20` bytes)
   - **Serialized Preimage (`74` bytes hex):**
     ```text
     10446976692d50512d53706f726b2d7631dff0c8f304aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1c2700008023a5f20000000000f1536500000000
     ```
   - **Resulting 64-Byte `prehash_msg = SHA-512(preimage)` (hex):**
     ```text
     fc80064a5487fc3a9f9152ff6002fca7b6f14f159f4b67be058b3df72e78982018b4bd345b0b77bc89e42db3a9817c6f75cd28b6caf877f963fc2bc7d0bd2783
     ```
