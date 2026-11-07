# DIP-PQ-0: Non-Consensus Harvest-Now-Decrypt-Later (HNDL) Hardening, C++ `CCrypter` `nDerivationMethod = 1`, and Vault-First Staking Hygiene

- **DIP:** `DIP-PQ-0`
- **Track:** Track 7B Phase 0 (`P0.1`, `P0.2`, `P0.3`)
- **Coordination Tier:** Tier A (Client-Local / Off-Chain) & Tier B (Capability-Negotiated P2P Transport)
- **Status:** Active Specification & Canonical Test Vector Suite (2026-11-07)
- **Applies To:** Canonical C++ Divi Core (`DiviProject/Divi`, `divid` v3.0.0) and Rust IronDivi (`DiviDomains/IronDivi`, `irondivid` v0.2.9+)
- **Parent Architecture Document:** [`docs/plans/post-quantum-lockstep.md`](./post-quantum-lockstep.md) (§2.2, §3 Tier A & Tier B, §6 Phase 0)

---

## 1. Abstract & Threat Model

Early fault-tolerant Cryptographically Relevant Quantum Computers (CRQCs) running Shor's algorithm will require hours to days per elliptic-curve discrete-logarithm recovery (`secp256k1`, `X25519`), rather than sub-minute mempool interception. Consequently, **Harvest-Now-Decrypt-Later (HNDL)** wire recordings and **long-lived on-chain public keys** (`CPubKey` revealed during direct Proof-of-Stake `vchBlockSig` signing or non-hardened `xpub` sharing) fail years before unspent `Hash160` outputs.

`DIP-PQ-0` specifies the four immediate, zero-consensus-fork upgrades that harden both `divid` (C++11) and `irondivid` (Rust) against HNDL collection, offline wallet brute-forcing, and premature on-chain public-key exposure:

1. **C++ `CCrypter` `nDerivationMethod = 1` (`P0.3a`):** Upgrades `divid` `wallet.dat` master-key derivation and secret-record wrapping from legacy unauthenticated `EVP_BytesToKey(SHA512)` + `AES-256-CBC` (`nDerivationMethod = 0`) to memory-hard `Argon2id(m=65536 KiB, t=3, p=1)` + `XChaCha20-Poly1305` AEAD with domain-separated Associated Data (`AAD`), matching `irondivid`'s [`crates/divi-wallet/src/at_rest.rs`](../../crates/divi-wallet/src/at_rest.rs) while preserving full backward compatibility for existing `nDerivationMethod = 0` wallets.
2. **Vault-First Staking Defaults & Hardened-Only HD Derivation (`P0.3b`):** Standardizes two-tier `STAKING_VAULT(ownerKeyHash, vaultKeyHash)` (`OP_IF <ownerKeyHash> OP_ELSE OP_REQUIRE_COINSTAKE <vaultKeyHash> OP_ENDIF OP_OVER OP_HASH160 OP_EQUALVERIFY OP_CHECKSIG`) as the default staking posture across CLI/WebUI wallets, keeping `ownerKeyHash` unrevealed behind `Hash160` while only the hot `vaultKeyHash` signs `vchBlockSig` coinstakes, alongside an opt-in hardened-only HD derivation tree (`m/44'/301'/account'/change'/index'`) that prevents parent `xpub` quantum escalation.
3. **Hybrid `X25519 + ML-KEM-768` Diagnostic Bundle Format (`P0.1`):** Upgrades `irondivi-cli diag` (`crates/divi-diag/src/consent.rs`) and `irondivi-diag-receiver` (`bin/irondivi-diag-receiver`) from classical `age::x25519` to hybrid post-quantum `X25519 + ML-KEM-768` (`FIPS 203`) recipients so diagnostic bundles uploaded over the public internet cannot be decrypted retroactively by a future CRQC.
4. **Capability-Negotiated Hybrid `v2` P2P Transport & `X25519MLKEM768` TLS (`P0.2`):** Specifies TLS 1.3 `X25519MLKEM768` (`0x11EC`) key exchange for Electrum (`-electrumtls`, `-electrumws`) and RPC endpoints, plus the capability-negotiated `NODE_P2P_V2_HYBRID` (`1 << 24`) P2P framing combining `X25519` + `ML-KEM-768` with `ChaCha20-Poly1305` AEAD packet encryption and automatic `v1` plaintext TCP fallback.

---

## 2. Specification `P0.3a`: C++ `divid` `CCrypter` `nDerivationMethod = 1` (`Argon2id` + `XChaCha20-Poly1305` AEAD)

### 2.1 Existing Legacy Format (`nDerivationMethod = 0`)

In C++ `divid` ([`divi/src/MasterKey.h:6-39`](../../../Divi/divi/src/MasterKey.h) and [`divi/src/crypter.cpp:21-193`](../../../Divi/divi/src/crypter.cpp)), BerkeleyDB `wallet.dat` stores one or more `CMasterKey` records under database key `("mkey", nMasterKeyId)`:

```cpp
class CMasterKey {
public:
    std::vector<unsigned char> vchCryptedKey;
    std::vector<unsigned char> vchSalt;
    unsigned int nDerivationMethod;
    unsigned int nDeriveIterations;
    std::vector<unsigned char> vchOtherDerivationParameters;
};
```

When `nDerivationMethod == 0`:
- `vchSalt` is `8` bytes (`WALLET_CRYPTO_SALT_SIZE = 8`).
- `CCrypter::BytesToKeySHA512AES(vchSalt, strPassphrase, nDeriveIterations, vchKey, vchIV)` computes iterative `SHA-512`:
  $$D_0 = \text{SHA512}(\text{strPassphrase} \parallel \text{vchSalt}), \quad D_i = \text{SHA512}(D_{i-1}) \text{ for } i \in [1, \text{nDeriveIterations}-1]$$
  yielding `vchKey = D_{n-1}[0..32]` (`32` bytes) and `vchIV = D_{n-1}[32..48]` (`16` bytes).
- `vchCryptedKey` is `AES-256-CBC` (PKCS#7 padded, `48` bytes) of the 32-byte `vMasterKey`.
- Each wallet private key in `mapCryptedKeys` (`("ckey", vchPubKey)`) and the encrypted HD chain `cryptedHDChain` (`"chdchain"`) is encrypted with `AES-256-CBC` under `vMasterKey` using `CHash256(vchPubKey)[0..16]` as the IV (`EncryptSecret` / `DecryptKey` in `divi/src/crypter.cpp:116-193`).
- **Weaknesses of `nDerivationMethod = 0`:** (a) Iterative `SHA-512` has zero memory hardness and is trivially parallelizable on GPUs/ASICs; (b) `AES-256-CBC` lacks an authentication tag (MAC), relying on PKCS#7 padding and `key.VerifyPubKey(vchPubKey)` during `Unlock`.

### 2.2 New Format (`nDerivationMethod = 1`) — Exact Parity with `irondivid` `at_rest.rs`

When creating a newly encrypted wallet (`encryptwallet`) or changing the wallet passphrase (`walletpassphrasechange`) under `DIP-PQ-0`, `CMasterKey` MUST be written with `nDerivationMethod = 1`, matching [`crates/divi-wallet/src/at_rest.rs:29-223`](../../crates/divi-wallet/src/at_rest.rs):

1. **Master-Key Record Fields (`CMasterKey` with `nDerivationMethod = 1`):**
   - `nDerivationMethod`: `1` (`uint32_t` little-endian in BDB serialization).
   - `vchSalt`: `16` cryptographically random bytes (`WALLET_CRYPTO_ARGON2_SALT_SIZE = 16`). *(Note: `CCrypter::SetKeyFromPassphrase` relaxes the legacy `chSalt.size() == 8` check when `nDerivationMethod == 1`, requiring `chSalt.size() == 16`.)*
   - `nDeriveIterations`: `3` (mirrors `t = 3` passes for legacy RPC inspection).
   - `vchOtherDerivationParameters`: Exactly `13` bytes matching `KdfParams::encode()` in `crates/divi-wallet/src/at_rest.rs:56-67`:
     ```text
     Byte 0      : 0x02 (KdfParams::VERSION = 2)
     Bytes 1..5  : m_kib (u32 LE, default 65536 = 0x00000100 = 64 MiB)
     Bytes 5..9  : t     (u32 LE, default 3     = 0x03000000)
     Bytes 9..13 : p     (u32 LE, default 1     = 0x01000000)
     ```
     Default 13-byte encoding: `02000001000300000001000000`.
     Any `vchOtherDerivationParameters` whose length is not `13`, whose version byte is not `0x02`, whose `m_kib > 4 * 1024 * 1024` (`4 GiB`), or whose `(m_kib, t, p)` parameters are rejected by RFC 9106 `Argon2id v0x13` MUST be rejected deterministically without attempting decryption.

2. **Passphrase Key Derivation (`Argon2id v0x13`):**
   - Algorithm: `Argon2id` (RFC 9106), version `0x13` (`19`), output tag length `32` bytes.
   - Inputs: `password = strKeyData` (UTF-8 passphrase bytes), `salt = vchSalt` (`16` bytes), `m_cost = m_kib`, `t_cost = t`, `p_cost = p`.
   - Output: `K_passphrase` (`32` bytes, zeroized on drop).

3. **Master-Key Sealing (`XChaCha20-Poly1305` with Domain-Separated `AAD`):**
   - Associated Data (`AAD`) binds the KDF cost record and salt to the ciphertext (`master_key_aad` in `at_rest.rs:158-163`):
     $$\text{AAD}_{\text{master}} = \texttt{"encrypted\_master\_key"} \text{ (20 B)} \parallel \text{vchOtherDerivationParameters} \text{ (13 B)} \parallel \text{vchSalt} \text{ (16 B)} \quad (\text{49 bytes total})$$
   - Nonce: `24` cryptographically random bytes (`XNonce`).
   - Plaintext: `vMasterKey` (`32` bytes).
   - `vchCryptedKey` layout (`72` bytes total):
     ```text
     [ XNonce (24 bytes) ] || [ XChaCha20-Poly1305 Ciphertext (32 bytes) ] || [ Poly1305 Tag (16 bytes) ]
     ```
   - On `Unlock`: if `XChaCha20-Poly1305::decrypt` fails or the decrypted plaintext length is not `32`, `Unlock` returns `false` (`WrongPassphrase`) immediately in constant time without iterating `mapCryptedKeys`.

4. **Per-Record Secret Wrapping (`ckey` and `chdchain` AEAD Binding):**
   - Under `nDerivationMethod = 1`, each secret record encrypted by `vMasterKey` uses `XChaCha20-Poly1305` with a fresh 24-byte random `XNonce` and binds the record's logical database key as `AAD` (`MasterKey::seal_record` in `at_rest.rs:120-126`):
     - For `("ckey", vchPubKey)`: $\text{AAD}_{\text{ckey}} = \texttt{"ckey"} \parallel \text{vchPubKey}$ (`4 + 33 = 37` bytes for compressed `CPubKey`). Plaintext is the 32-byte secret scalar; sealed `vchCryptedSecret` is `24 + 32 + 16 = 72` bytes.
     - For `"chdchain"`: $\text{AAD}_{\text{hd}} = \texttt{"chdchain"}$ (`8` bytes).
   - **Backward Compatibility Invariant:**
     - `CCrypter` and `CCryptoKeyStore` inspect `CMasterKey::nDerivationMethod`:
       - If `nDerivationMethod == 0`, `divid` executes the legacy `BytesToKeySHA512AES` + `AES-256-CBC` path (`vchCryptedKey.size() == 48`, `vchCryptedSecret.size() == 48`).
       - If `nDerivationMethod == 1`, `divid` executes the `Argon2id` + `XChaCha20-Poly1305` AEAD path (`vchCryptedKey.size() == 72`, `vchCryptedSecret.size() == 72`).
       - Upon `walletpassphrasechange` (or `-upgradewalletCrypto=1`), `divid` re-wraps all `ckey` and `chdchain` records under a fresh `nDerivationMethod = 1` `CMasterKey` atomically inside a single BDB transaction.

---

## 3. Specification `P0.3b`: Vault-First Staking Defaults & Hardened-Only HD Derivation

### 3.1 Vault-First Staking Insulation Against Shor's Algorithm

In both `divid` (`divi/src/BlockSigning.cpp:128-139`) and `irondivid` (`crates/divi-node/src/staker.rs:1008-1038`), every Proof-of-Stake block header carries a 65-byte compact recoverable `secp256k1` signature (`vchBlockSig`), from which every peer recovers the full 33-byte `CPubKey` (`RecoverCompact`) on the very first block a UTXO mints.

- **Direct `P2PKH` Staking Risk:** If a holder stakes directly from a standard `P2PKH` address (`OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG`), the first minted block permanently publishes the spending `CPubKey` on-chain, exposing the entire UTXO principal to offline Shor key recovery.
- **Staking Vault Architectural Insulation (`STAKING_VAULT`):**
  Divi's 2-key Staking Vault script ([`divi/src/script/StakingVaultScript.cpp:9-12`](../../../Divi/divi/src/script/StakingVaultScript.cpp), [`crates/divi-script/src/vault.rs:19-27`](../../crates/divi-script/src/vault.rs)) is a `49`-byte `scriptPubKey`:
  ```text
  OP_IF (0x63)
      0x14 <ownerPubKeyHash (20 bytes)>
  OP_ELSE (0x67)
      OP_REQUIRE_COINSTAKE (0xb9) 0x14 <vaultPubKeyHash (20 bytes)>
  OP_ENDIF (0x68)
  OP_OVER (0x78) OP_HASH160 (0xa9) OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
  ```
  During PoS coinstake signing (`OP_FALSE` branch):
  1. Only the hot manager key (`vaultPubKey`) is pushed in the coinstake `scriptSig` and used to sign `vchBlockSig`.
  2. The cold owner key (`ownerPubKey`) is **never** revealed on-chain during funding or staking; it remains protected behind `Hash160(ownerPubKey) = RIPEMD160(SHA256(ownerPubKey))` until an explicit owner withdrawal (`OP_TRUE` branch).
  3. Consensus rules (`divi/src/BlockTransactionChecker.cpp:57-109` and `crates/divi-consensus/`) strictly require every coinstake spending the `OP_FALSE` vault branch to return `>= 100%` of the vault principal + PoS block reward back to the **exact same `vaultScript`**, burn transaction fees, and credit any lottery win to `vaultScript`.
  4. Therefore, even if a future quantum adversary recovers the private key of `vaultPubKey` via Shor's algorithm, the adversary **cannot spend or redirect the vault's principal or rewards** (`OP_REQUIRE_COINSTAKE` rejects non-coinstake spends, and consensus rejects coinstake outputs that alter `vaultScript`).

### 3.2 Mandatory Wallet UX & CLI Defaults (`divid` & `irondivid`)

1. **WebUI & Wallet Staking Wizard Default:** The built-in Node WebUI (`crates/divi-webui` Pillar 3 Staking & Vaults) and `irondivi-cli` / `divi-cli` staking setup flows MUST default to **Vault Staking (`fundvault`)** rather than direct `P2PKH` staking whenever a user enables staking on an unvaulted balance.
2. **One-Shot Owner-Withdrawal Hygiene (Zero Owner Address Reuse):** When an owner spends from a Staking Vault via the `OP_IF` owner branch (`reclaimvaultfunds` / `removevault`), the wallet MUST automatically generate a **fresh, never-before-used owner `KeyHash`** for any change or re-vaulted output so the revealed `ownerPubKey` never holds residual funds.
3. **`getstakingstatus` Quantum Hygiene Advisory:** Both `irondivid` and `divid` expose `vault_insulation` telemetry in `getstakingstatus` / `getdiaginfo`:
   - `"vault_only"`: `100%` of staking UTXOs are `STAKING_VAULT` scripts with unrevealed `ownerPubKeyHash` (quantum-insulated principal).
   - `"mixed_or_direct_p2pkh"`: Warns operator when non-vault `P2PKH` UTXOs with exposed `CPubKey` are actively staking.

### 3.3 Hardened-Only HD Derivation Option (`m/44'/coin'/account'/change'/index'`)

In classical BIP32/BIP44 ([`crates/divi-wallet/src/hd.rs:16-21`](../../crates/divi-wallet/src/hd.rs)), the path `m/44'/301'/account'/change/index` uses non-hardened derivation for `change` (`0` or `1`) and `index`. If a user exports an account extended public key (`xpub` at `m/44'/301'/account'`) and any single child public key is also exposed, or if a CRQC applies Shor's algorithm to the parent `xpub`'s compressed `secp256k1` point, every non-hardened child private key under that account is compromised.

`DIP-PQ-0` defines the **Hardened-Only BIP44 Account Mode** (`-hdhardenedonly=1` / `WalletKeyHygiene::HardenedOnly`):
- **Divi Mainnet Path:** `m / 44' / 301' / account' / change' / index'`
- **PrivateDivi Mainnet Path:** `m / 44' / 801' / account' / change' / index'`
- **Testnet / Regtest Path:** `m / 44' / 1' / account' / change' / index'`
- **Vault Dedicated Subtrees (`account' = 0'`):**
  - Cold Vault Owner Keys: `m / 44' / 301' / 0' / 2' / index'` (all hardened; `ownerPubKey` never leaves cold storage, only `Hash160(ownerPubKey)` is exported to the hot node).
  - Hot Vault Manager Keys: `m / 44' / 301' / 0' / 3' / index'` (all hardened).
- Because hardened BIP32 derivation computes `HMAC-SHA512(Key = c_par, Data = 0x00 || ser256(k_par) || ser32(index + 2^31))`, recovering a child private key $k_i$ via Shor's algorithm reveals **zero information** about sibling keys $k_j$ ($j \ne i$) or the parent key $k_{\text{par}}$ (protected by $2^{128}$ Grover preimage resistance of `HMAC-SHA512`).

---

## 4. Specification `P0.1`: Hybrid `X25519 + ML-KEM-768` Diagnostic Bundle Format (`divi-diag`)

### 4.1 Recipient & Envelope Upgrade

[`crates/divi-diag/src/consent.rs:46-59`](../../crates/divi-diag/src/consent.rs) currently encrypts redacted `<folder>.tar.zst` diagnostic archives to a classical `age1...` (`X25519`) developer recipient (`DEV_KEY`) before uploading to `PUT https://diag.irondivi.com/v1/upload` ([`bin/irondivi-diag-receiver/src/lib.rs:5-25`](../../bin/irondivi-diag-receiver/src/lib.rs)).

Under `DIP-PQ-0` (`P0.1`), diagnostic packages upgrade to a **Hybrid `X25519 + ML-KEM-768` (`FIPS 203`)** key-encapsulation stanza:

1. **Developer Hybrid Public Key (`DevKey` v2):**
   - Contains both the classical 32-byte `X25519` public key ($pk_{\text{X25519}}$, `32 B`) and the NIST FIPS 203 `ML-KEM-768` encapsulation key ($ek_{\text{ML-KEM-768}}$, `1,184 B`), encoded as an `age1pq1...` Bech32 recipient string (or dual stanza header `-> X25519-MLKEM768 <ephemeral_x25519_b64> <mlkem768_ct_b64>`).
   - Fingerprint displayed at user consent prompt (`consent.rs:51`): first 16 hex characters of `SHA-256(recipient_canonical_bytes)`.

2. **Hybrid KEM Combiner (`HKDF-SHA256`):**
   Given fresh OS randomness $(r_{\text{X25519}} \in \{0,1\}^{256}, m_{\text{KEM}} \in \{0,1\}^{256})$:
   - Classical ECDH: $(epk_{\text{X25519}}, ss_{\text{X25519}}) = \text{X25519}(r_{\text{X25519}}, pk_{\text{X25519}})$ (`32 B` public ephemeral, `32 B` shared secret).
   - Post-Quantum KEM: $(ct_{\text{KEM}}, ss_{\text{KEM}}) = \text{ML-KEM-768.Encaps}(ek_{\text{ML-KEM-768}}, m_{\text{KEM}})$ (`1,088 B` ciphertext, `32 B` shared secret).
   - Combined Wrap Key (`32 B`):
     $$\text{IKM} = ss_{\text{X25519}} \text{ (32 B)} \parallel ss_{\text{KEM}} \text{ (32 B)}$$
     $$\text{Salt} = epk_{\text{X25519}} \text{ (32 B)} \parallel pk_{\text{X25519}} \text{ (32 B)} \parallel \text{SHA256}(ct_{\text{KEM}}) \text{ (32 B)} \parallel \text{SHA256}(ek_{\text{ML-KEM-768}}) \text{ (32 B)}$$
     $$K_{\text{wrap}} = \text{HKDF-SHA256}(\text{Salt}, \text{IKM}, \text{info}=\texttt{"age-encryption.org/v1/X25519-MLKEM768"}, L=32)$$
   - The 16-byte `age` file key is wrapped with `ChaCha20-Poly1305(K_wrap, nonce = 0^12, plaintext = file_key)` (`32 B` body), and the payload stream is encrypted with `age` STREAM (`ChaCha20-Poly1305` in `64 KiB` chunks).
   - **Security Guarantee:** `K_wrap` remains indistinguishable from random as long as *either* `X25519` is unbroken *or* `ML-KEM-768` (`IND-CCA2` Module-LWE) is unbroken.

3. **Receiver Validation (`irondivi-diag-receiver`):**
   - `bin/irondivi-diag-receiver/src/lib.rs:57` continues to verify the `age-encryption.org/v1\n` magic header on `PUT /v1/upload` before writing to disk, enforcing the `100 MiB` cap (`CAP`), `10/hour` and `1 GB/day` in-memory keyed-hash rate limits, and 90-day retention sweep.

---

## 5. Specification `P0.2`: Hybrid `X25519MLKEM768` TLS 1.3 & Capability-Negotiated `v2` P2P Transport

### 5.1 Electrum & RPC TLS 1.3 (`X25519MLKEM768`)

1. **Rust `irondivid` (`crates/divi-electrum` & `bin/irondivid`):**
   - Configure `rustls 0.23+` crypto provider (`rustls-post-quantum` / `aws-lc-rs` or hybrid KX provider) advertising IANA TLS 1.3 named group **`X25519MLKEM768` (`0x11EC`)** first in `kx_groups`, followed by classical `X25519` (`0x001D`) and `secp256r1` (`0x0017`) fallback for legacy Electrum clients.
2. **Nginx / OpenSSL Frontends (`dnsdivi`, `vps1`):**
   - Configure `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;` on `electrum.irondivi.com`, `wallet.irondivi.com`, `divi.cx`, and `diag.irondivi.com`.

### 5.2 Tier B Capability-Negotiated P2P `v2` Hybrid Framing (`divid` & `irondivid`)

To protect peer-to-peer transaction and block relay against passive ISP/backbone wiretapping without breaking compatibility with existing `v1` nodes:

1. **Service Bit & Handshake Negotiation:**
   - Service bit: `NODE_P2P_V2_HYBRID = (1ULL << 24)` (`0x01000000`).
   - Initiator connects and sends a 12-byte `v2` magic prefix (`SHA256("Divi-P2P-v2-Magic" || network_magic)[0..12]`) followed by `epk_X25519 (32 B) || ek_MLKEM768 (1,184 B)` (`1,228` bytes total).
   - If the responder supports `v2`, it replies with `epk_resp_X25519 (32 B) || ct_MLKEM768 (1,088 B)` (`1,120` bytes). If the responder is a legacy `v1` node (which expects the 4-byte network magic `0xdff0c8f3` on mainnet), it disconnects or rejects the prefix, and the initiator immediately falls back to `v1` plaintext TCP and caches the peer's `v1` status.
2. **Session Key Schedule & AEAD Framing:**
   - Transcript hash:
     $$H = \text{SHA256}(\texttt{"Divi-P2P-v2-Transcript"} \parallel \text{network\_magic (4 B)} \parallel epk_{\text{init}} \parallel ek_{\text{KEM}} \parallel epk_{\text{resp}} \parallel ct_{\text{KEM}})$$
   - Master PRK:
     $$\text{PRK} = \text{HKDF-Extract}(\text{salt} = H, \text{IKM} = ss_{\text{X25519}} \parallel ss_{\text{ML-KEM-768}})$$
   - Directional keys & session ID (inspired by BIP-324 + FIPS 203):
     - $K_{\text{init}\to\text{resp}}^{\text{len}} = \text{HKDF-Expand}(\text{PRK}, \texttt{"divi\_v2\_init\_len"}, 32)$
     - $K_{\text{init}\to\text{resp}}^{\text{pkt}} = \text{HKDF-Expand}(\text{PRK}, \texttt{"divi\_v2\_init\_pkt"}, 32)$
     - $K_{\text{resp}\to\text{init}}^{\text{len}} = \text{HKDF-Expand}(\text{PRK}, \texttt{"divi\_v2\_resp\_len"}, 32)$
     - $K_{\text{resp}\to\text{init}}^{\text{pkt}} = \text{HKDF-Expand}(\text{PRK}, \texttt{"divi\_v2\_resp\_pkt"}, 32)$
     - $\text{SessionID} = \text{HKDF-Expand}(\text{PRK}, \texttt{"divi\_v2\_session\_id"}, 32)$
   - Each P2P message frame encodes a 3-byte little-endian length encrypted under `FSChaCha20` (`K_len`), followed by `[1-byte flags || 1-byte short command ID (or 12-byte ASCII command) || payload]` sealed with `FSChaCha20Poly1305` (`K_pkt`, 16-byte tag, automatic rekey every `224` messages).

---

## 6. Canonical Phase 0 Test Vectors (`tests/vectors/pq/dip_pq_0_vectors.json`)

Both `divid` (`divi/src/test/crypter_tests.cpp`) and `irondivid` (`crates/divi-wallet/src/at_rest.rs`) MUST pass the following deterministic test vectors:

### Vector 1: `KdfParams` Serialization & Master-Key `AAD` (`P0.3a`)

- **Parameters:** `m_kib = 65536` (`64 MiB`), `t = 3`, `p = 1`, `VERSION = 2`
- **Encoded `vchOtherDerivationParameters` (13 bytes hex):**
  ```text
  02000001000300000001000000
  ```
  *(Breakdown: `02` version, `00000100` = `65536` LE, `03000000` = `3` LE, `01000000` = `1` LE)*
- **Salt (`vchSalt`, 16 bytes hex):**
  ```text
  000102030405060708090a0b0c0d0e0f
  ```
- **Master-Key `AAD` (`49` bytes = `"encrypted_master_key"` + `KdfParams` + `vchSalt`):**
  ```text
  656e637279707465645f6d61737465725f6b657902000001000300000001000000000102030405060708090a0b0c0d0e0f
  ```

### Vector 2: `Argon2id v0x13` Key Derivation & `XChaCha20-Poly1305` Sealing (`P0.3a`)

- **Reference Vector A (matches `at_rest.rs:331-344`):**
  - `m_kib = 65536`, `t = 2`, `p = 1`
  - `passphrase`: `"password"` (`70617373776f7264`)
  - `salt`: `"somesalt"` (`736f6d6573616c74`)
  - `Derived 32-byte Key`:
    ```text
    09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7
    ```
- **Production Default Vector B (`nDerivationMethod = 1`):**
  - `m_kib = 65536`, `t = 3`, `p = 1` (`KdfParams::DEFAULT`)
  - `passphrase`: `"divi-pq-phase0-passphrase"`
  - `salt` (`16` bytes): `000102030405060708090a0b0c0d0e0f`
  - `vMasterKey` (`32` bytes): `1111111111111111111111111111111111111111111111111111111111111111`
  - `Deterministic Test XNonce` (`24` bytes): `222222222222222222222222222222222222222222222222`
  - `AAD`: `656e637279707465645f6d61737465725f6b657902000001000300000001000000000102030405060708090a0b0c0d0e0f`
  - **Verification Rule:** Flipping any single bit in `XNonce`, ciphertext, tag, `vchSalt`, or `vchOtherDerivationParameters` MUST return `Err(WalletError::WrongPassphrase)` in Rust and `false` in `CCrypter::DecryptMasterKey` in C++.

### Vector 3: Canonical 2-Key `STAKING_VAULT` Script Template (`P0.3b`)

- **`ownerPubKeyHash` (20 bytes):** `101112131415161718191a1b1c1d1e1f20212223`
- **`vaultPubKeyHash` (20 bytes):** `a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3`
- **Canonical 49-Byte `scriptPubKey` (identical in `StakingVaultScript.cpp:9-12` and `vault.rs:87-111`):**
  ```text
  6314101112131415161718191a1b1c1d1e1f2021222367b914a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b36878a988ac
  ```
  - Byte `0`: `0x63` (`OP_IF`)
  - Bytes `1..22`: `0x14` + `ownerPubKeyHash` (`20` bytes)
  - Byte `22`: `0x67` (`OP_ELSE`)
  - Byte `23`: `0xb9` (`OP_REQUIRE_COINSTAKE`)
  - Bytes `24..45`: `0x14` + `vaultPubKeyHash` (`20` bytes)
  - Byte `45`: `0x68` (`OP_ENDIF`)
  - Bytes `46..49`: `0x78` (`OP_OVER`), `0xa9` (`OP_HASH160`), `0x88` (`OP_EQUALVERIFY`), `0xac` (`OP_CHECKSIG`)

### Vector 4: Hardened-Only HD Derivation (`P0.3b`)

- **BIP39 24-Word Mnemonic:**
  `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art`
- **BIP39 Passphrase Variant A (`""` empty passphrase):**
  - **BIP39 64-Byte Seed (hex):**
    ```text
    408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840
    ```
  - **Master `XPrv` Chain Code & Secret Key (`HMAC-SHA512("Bitcoin seed", seed)`):**
    - `secret_key` (`I_L`): `235b34cd7c9f6d7e4595ffe9ae4b1cb5606df8aca2b527d20a07c8f56b2342f4`
    - `chain_code` (`I_R`): `f40eaad21641ca7cb5ac00f9ce21cac9ba070bb673a237f7bce57acda54386a4`
- **BIP39 Passphrase Variant B (`"TREZOR"` reference vector passphrase):**
  - **BIP39 64-Byte Seed (hex):**
    ```text
    bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8
    ```
  - **Master `XPrv` Chain Code & Secret Key (`HMAC-SHA512("Bitcoin seed", seed)`):**
    - `secret_key` (`I_L`): `c8b4073ccfcc63475c3d5202c6594484ee4e77b867cde3c3b46432fd71b467ae`
    - `chain_code` (`I_R`): `61ccb2bbe7d2a4fccd5f418ee931db7cbac9a153ec43b0ae3759ff991e4d23d1`
- **Hardened-Only Derivation Paths:**
  - Standard Spend Leaf: `m/44'/301'/0'/0'/0'` (indices `[0x8000002C, 0x8000012D, 0x80000000, 0x80000000, 0x80000000]`)
  - Cold Vault Owner Leaf: `m/44'/301'/0'/2'/0'` (indices `[0x8000002C, 0x8000012D, 0x80000000, 0x80000002, 0x80000000]`)
  - Hot Vault Manager Leaf: `m/44'/301'/0'/3'/0'` (indices `[0x8000002C, 0x8000012D, 0x80000000, 0x80000003, 0x80000000]`)
- **Cross-Client Invariant:** Neither `m/44'/301'/0'` nor `m/44'/301'/0'/0'` permits non-hardened `XPub::derive_child` derivation in Hardened-Only mode; `dumpwallet` / `dumphdinfo` records `hd_hardened_only=1`.
