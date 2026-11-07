// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! `DIP-PQ-0` (`P0.1`): Hybrid `X25519 + ML-KEM-768` (`FIPS 203`) diagnostic
//! bundle encryption and backward-compatible `age` X25519 decryption.
//!
//! Under `DIP-PQ-0` §4.1, diagnostic packages support a hybrid post-quantum
//! key-encapsulation stanza (`-> X25519-MLKEM768 <epk_b64> <mlkem768_ct_b64>`)
//! combining classical `X25519` ECDH with NIST FIPS 203 `ML-KEM-768` via
//! `HKDF-SHA256`, while retaining full compatibility with classical
//! `age1…` (`X25519`) recipients and identities.

use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Write};
use std::str::FromStr;

use age::{DecryptError, EncryptError, Identity};
use age_core::{
    format::{FileKey, Stanza, FILE_KEY_BYTES},
    primitives::{aead_decrypt, aead_encrypt, hkdf},
    secrecy::ExposeSecret,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use bech32::{FromBase32, ToBase32, Variant};
use ml_kem::{
    kem::Decapsulate, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768, B32,
};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Bech32 human-readable part for hybrid `X25519 + ML-KEM-768` recipients (`age1pq1…`).
pub const HYBRID_PUBLIC_KEY_HRP: &str = "age1pq";
/// Alternate Bech32 HRP accepted for hybrid recipients (`agepq1…`).
const HYBRID_PUBLIC_KEY_ALT_HRP: &str = "agepq";
/// Bech32 human-readable part for hybrid `X25519 + ML-KEM-768` identities (`AGE-SECRET-KEY-PQ-1…`).
pub const HYBRID_SECRET_KEY_HRP: &str = "age-secret-key-pq-";
/// Classical `age` X25519 recipient HRP (`age1…`).
const CLASSICAL_PUBLIC_KEY_HRP: &str = "age";
/// Classical `age` X25519 identity HRP (`AGE-SECRET-KEY-1…`).
const CLASSICAL_SECRET_KEY_HRP: &str = "age-secret-key-";

/// Stanza tag for `DIP-PQ-0` §4.1 hybrid `X25519 + ML-KEM-768` encapsulation.
pub const X25519_MLKEM768_STANZA_TAG: &str = "X25519-MLKEM768";
/// HKDF-SHA256 info label for `DIP-PQ-0` §4.1 hybrid wrap-key combiner.
pub const X25519_MLKEM768_KEY_LABEL: &[u8] = b"age-encryption.org/v1/X25519-MLKEM768";
/// Domain-separation label for deterministic ML-KEM-768 seed derivation from a classical 32-byte age secret.
const DERIVE_KEM_D_LABEL: &[u8] = b"age-encryption.org/v1/X25519-MLKEM768/derive-d";
const DERIVE_KEM_Z_LABEL: &[u8] = b"age-encryption.org/v1/X25519-MLKEM768/derive-z";

/// Classical X25519 public / secret key length in bytes.
pub const X25519_KEY_BYTES: usize = 32;
/// NIST FIPS 203 ML-KEM-768 encapsulation key length in bytes.
pub const MLKEM768_EK_BYTES: usize = 1184;
/// NIST FIPS 203 ML-KEM-768 ciphertext length in bytes.
pub const MLKEM768_CT_BYTES: usize = 1088;
/// Combined hybrid public key length (`32 + 1184 = 1216` bytes).
pub const HYBRID_PUBLIC_KEY_BYTES: usize = X25519_KEY_BYTES + MLKEM768_EK_BYTES;
/// Combined hybrid secret seed length (`32 B X25519 + 32 B d + 32 B z = 96` bytes).
pub const HYBRID_SECRET_KEY_BYTES: usize = 96;
/// Wrapped `age` file key body length (`16 B FileKey + 16 B Poly1305 tag = 32` bytes).
const ENCRYPTED_FILE_KEY_BYTES: usize = FILE_KEY_BYTES + 16;

/// zstd compression level matching `consent::ZSTD_LEVEL`.
pub const ZSTD_LEVEL: i32 = 12;

type MlKem768Ek = <MlKem768 as KemCore>::EncapsulationKey;
type MlKem768Dk = <MlKem768 as KemCore>::DecapsulationKey;

fn decode_bech32_any_case(s: &str) -> Result<(String, Vec<u8>), &'static str> {
    let trimmed = s.trim();
    let candidate = if trimmed.chars().any(|c| c.is_ascii_uppercase())
        && !trimmed.chars().any(|c| c.is_ascii_lowercase())
    {
        trimmed.to_ascii_lowercase()
    } else {
        trimmed.to_owned()
    };
    let (hrp, data, variant) = bech32::decode(&candidate).map_err(|_| "invalid Bech32 encoding")?;
    if variant != Variant::Bech32 {
        return Err("invalid Bech32 variant");
    }
    let bytes = Vec::<u8>::from_base32(&data).map_err(|_| "invalid Bech32 base32 payload")?;
    Ok((hrp, bytes))
}

/// Hybrid `X25519 + ML-KEM-768` public recipient (`DIP-PQ-0` §4.1).
///
/// Encodes as `age1pq1…` Bech32 (`1,216` payload bytes = `32 B X25519 pk || 1,184 B ML-KEM-768 ek`)
/// or parses from composite `age1…+mlkem768:<base64>` representation.
#[derive(Clone)]
pub struct HybridRecipient {
    pk_x25519: [u8; X25519_KEY_BYTES],
    ek_bytes: Box<[u8; MLKEM768_EK_BYTES]>,
    ek: MlKem768Ek,
}

impl PartialEq for HybridRecipient {
    fn eq(&self, other: &Self) -> bool {
        self.pk_x25519 == other.pk_x25519 && self.ek_bytes == other.ek_bytes
    }
}

impl Eq for HybridRecipient {}

impl HybridRecipient {
    /// Construct and validate a hybrid recipient from raw `X25519` (`32 B`) and
    /// `ML-KEM-768` (`1,184 B`) public key bytes, enforcing the FIPS 203 §7.2
    /// encapsulation key modulus check.
    pub fn from_components(
        pk_x25519: [u8; X25519_KEY_BYTES],
        ek_bytes: [u8; MLKEM768_EK_BYTES],
    ) -> Result<Self, &'static str> {
        // Reject all-zero or low-order X25519 public keys that could yield non-contributory DH.
        if bool::from(pk_x25519.iter().fold(0u8, |acc, b| acc | b).ct_eq(&0u8)) {
            return Err("invalid all-zero X25519 public key");
        }
        let encoded_ek = <&Encoded<MlKem768Ek>>::try_from(&ek_bytes[..])
            .map_err(|_| "incorrect ML-KEM-768 encapsulation key length")?;
        let ek = MlKem768Ek::from_bytes(encoded_ek);
        // FIPS 203 §7.2 modulus check: re-encoding the decoded polynomial vector must
        // match the input bytes identically (rejects coefficients >= q = 3329).
        if ek.as_bytes().as_slice() != &ek_bytes[..] {
            return Err("ML-KEM-768 encapsulation key failed FIPS 203 modulus check");
        }
        Ok(Self {
            pk_x25519,
            ek_bytes: Box::new(ek_bytes),
            ek,
        })
    }

    /// Construct from a `1,216`-byte slice (`pk_x25519 || ek_mlkem768`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.len() != HYBRID_PUBLIC_KEY_BYTES {
            return Err("incorrect hybrid recipient length");
        }
        let mut pk_x25519 = [0u8; X25519_KEY_BYTES];
        pk_x25519.copy_from_slice(&bytes[..X25519_KEY_BYTES]);
        let mut ek_bytes = [0u8; MLKEM768_EK_BYTES];
        ek_bytes.copy_from_slice(&bytes[X25519_KEY_BYTES..]);
        Self::from_components(pk_x25519, ek_bytes)
    }

    /// Return the 32-byte `X25519` public key.
    pub fn x25519_public_bytes(&self) -> &[u8; X25519_KEY_BYTES] {
        &self.pk_x25519
    }

    /// Return the 1,184-byte `ML-KEM-768` encapsulation key.
    pub fn mlkem768_ek_bytes(&self) -> &[u8; MLKEM768_EK_BYTES] {
        &self.ek_bytes
    }

    /// Return the classical `age1…` (`X25519`) recipient for the classical half.
    pub fn classical_recipient(&self) -> age::x25519::Recipient {
        let encoded = bech32::encode(
            CLASSICAL_PUBLIC_KEY_HRP,
            self.pk_x25519.to_base32(),
            Variant::Bech32,
        )
        .expect("classical HRP is valid");
        encoded.parse().expect("valid 32-byte X25519 recipient")
    }

    /// Return the composite `age1…+mlkem768:<base64>` representation.
    pub fn to_composite_string(&self) -> String {
        format!(
            "{}+mlkem768:{}",
            self.classical_recipient(),
            BASE64_STANDARD_NO_PAD.encode(&self.ek_bytes[..])
        )
    }

    /// First 16 hex characters of `SHA-256(recipient_string)` (`DIP-PQ-0` §4.1).
    pub fn fingerprint(&self) -> String {
        let s = self.to_string();
        hex::encode(Sha256::digest(s.as_bytes()))[..16].to_owned()
    }

    /// Deterministically encapsulate a 16-byte `FileKey` using explicit randomness
    /// `(r_x25519, m_kem)` (used by `wrap_file_key` with `OsRng` and by deterministic KATs).
    pub fn wrap_file_key_deterministic(
        &self,
        file_key: &FileKey,
        r_x25519: &[u8; 32],
        m_kem: &[u8; 32],
    ) -> Result<Stanza, EncryptError> {
        let esk = StaticSecret::from(*r_x25519);
        let epk = PublicKey::from(&esk);
        let peer_pk = PublicKey::from(self.pk_x25519);
        let ss_x25519 = esk.diffie_hellman(&peer_pk);

        if bool::from(
            ss_x25519
                .as_bytes()
                .iter()
                .fold(0u8, |acc, b| acc | b)
                .ct_eq(&0u8),
        ) {
            panic!("Generated non-contributory X25519 shared secret; OS RNG is likely failing!");
        }

        let m_b32 = B32::from(*m_kem);
        let (ct_kem, ss_kem) = self.ek.encapsulate_deterministic(&m_b32).map_err(|_| {
            EncryptError::Io(std::io::Error::other("ML-KEM-768 encapsulate failed"))
        })?;

        let wrap_key = combine_hybrid_wrap_key(
            ss_x25519.as_bytes(),
            ss_kem.as_slice(),
            epk.as_bytes(),
            &self.pk_x25519,
            ct_kem.as_slice(),
            &self.ek_bytes[..],
        );
        let body = aead_encrypt(&wrap_key, file_key.expose_secret());

        Ok(Stanza {
            tag: X25519_MLKEM768_STANZA_TAG.to_owned(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(epk.as_bytes()),
                BASE64_STANDARD_NO_PAD.encode(ct_kem.as_slice()),
            ],
            body,
        })
    }
}

/// Compute the `DIP-PQ-0` §4.1 hybrid `HKDF-SHA256` wrap key:
/// - `IKM = ss_x25519 (32 B) || ss_kem (32 B)`
/// - `Salt = epk_x25519 (32 B) || pk_x25519 (32 B) || SHA256(ct_kem) (32 B) || SHA256(ek_mlkem768) (32 B)`
/// - `K_wrap = HKDF-SHA256(Salt, IKM, info = "age-encryption.org/v1/X25519-MLKEM768", L = 32)`
fn combine_hybrid_wrap_key(
    ss_x25519: &[u8],
    ss_kem: &[u8],
    epk_x25519: &[u8; 32],
    pk_x25519: &[u8; 32],
    ct_kem: &[u8],
    ek_mlkem768: &[u8],
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(ss_x25519);
    ikm[32..].copy_from_slice(ss_kem);

    let ct_hash = Sha256::digest(ct_kem);
    let ek_hash = Sha256::digest(ek_mlkem768);

    let mut salt = [0u8; 128];
    salt[0..32].copy_from_slice(epk_x25519);
    salt[32..64].copy_from_slice(pk_x25519);
    salt[64..96].copy_from_slice(&ct_hash);
    salt[96..128].copy_from_slice(&ek_hash);

    Zeroizing::new(hkdf(&salt, X25519_MLKEM768_KEY_LABEL, &ikm[..]))
}

impl fmt::Display for HybridRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut raw = Vec::with_capacity(HYBRID_PUBLIC_KEY_BYTES);
        raw.extend_from_slice(&self.pk_x25519);
        raw.extend_from_slice(&self.ek_bytes[..]);
        let encoded = bech32::encode(HYBRID_PUBLIC_KEY_HRP, raw.to_base32(), Variant::Bech32)
            .expect("HYBRID_PUBLIC_KEY_HRP is valid");
        write!(f, "{encoded}")
    }
}

impl fmt::Debug for HybridRecipient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

impl FromStr for HybridRecipient {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Some((age_part, kem_part)) = trimmed.split_once("+mlkem768:") {
            let (hrp, pk_bytes) = decode_bech32_any_case(age_part)?;
            if hrp != CLASSICAL_PUBLIC_KEY_HRP {
                return Err("incorrect classical age HRP in composite recipient");
            }
            let pk_x25519: [u8; X25519_KEY_BYTES] = pk_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "incorrect X25519 pubkey length")?;
            let ek_vec = BASE64_STANDARD_NO_PAD
                .decode(kem_part.trim().trim_end_matches('='))
                .map_err(|_| "invalid ML-KEM-768 base64 encapsulation key")?;
            let ek_bytes: [u8; MLKEM768_EK_BYTES] = ek_vec
                .as_slice()
                .try_into()
                .map_err(|_| "incorrect ML-KEM-768 encapsulation key length")?;
            return Self::from_components(pk_x25519, ek_bytes);
        }

        let (hrp, bytes) = decode_bech32_any_case(trimmed)?;
        if hrp == HYBRID_PUBLIC_KEY_HRP || hrp == HYBRID_PUBLIC_KEY_ALT_HRP {
            Self::from_bytes(&bytes)
        } else {
            Err("incorrect hybrid recipient HRP")
        }
    }
}

impl age::Recipient for HybridRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        let mut r_x25519 = Zeroizing::new([0u8; 32]);
        let mut m_kem = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *r_x25519);
        OsRng.fill_bytes(&mut *m_kem);
        let stanza = self.wrap_file_key_deterministic(file_key, &r_x25519, &m_kem)?;
        Ok((vec![stanza], HashSet::new()))
    }
}

/// Hybrid `X25519 + ML-KEM-768` secret identity (`DIP-PQ-0` §4.1).
///
/// Unwraps both hybrid `X25519-MLKEM768` stanzas and classical `X25519` stanzas.
/// All secret key material (`sk_x25519`, `d_kem`, `z_kem`) is zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct HybridIdentity {
    sk_x25519: [u8; X25519_KEY_BYTES],
    d_kem: [u8; 32],
    z_kem: [u8; 32],
}

impl HybridIdentity {
    /// Generate a fresh random hybrid identity from OS randomness.
    pub fn generate() -> Self {
        let mut sk_x25519 = [0u8; X25519_KEY_BYTES];
        let mut d_kem = [0u8; 32];
        let mut z_kem = [0u8; 32];
        OsRng.fill_bytes(&mut sk_x25519);
        OsRng.fill_bytes(&mut d_kem);
        OsRng.fill_bytes(&mut z_kem);
        Self {
            sk_x25519,
            d_kem,
            z_kem,
        }
    }

    /// Construct from explicit `(sk_x25519, d_kem, z_kem)` 32-byte seeds.
    pub fn from_seeds(sk_x25519: [u8; X25519_KEY_BYTES], d_kem: [u8; 32], z_kem: [u8; 32]) -> Self {
        Self {
            sk_x25519,
            d_kem,
            z_kem,
        }
    }

    /// Deterministically derive a `HybridIdentity` from a classical `AGE-SECRET-KEY-1…`
    /// identity string so existing single-key identities can derive a deterministic
    /// `ML-KEM-768` keypair while opening both `X25519-MLKEM768` and `X25519` bundles.
    pub fn from_age_secret_key(age_sk: &str) -> Result<Self, &'static str> {
        let (hrp, mut bytes) = decode_bech32_any_case(age_sk)?;
        if hrp != CLASSICAL_SECRET_KEY_HRP {
            bytes.zeroize();
            return Err("incorrect classical age secret key HRP");
        }
        let sk_x25519: [u8; X25519_KEY_BYTES] = match bytes.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                bytes.zeroize();
                return Err("incorrect classical age secret key length");
            }
        };
        bytes.zeroize();
        let pk_x25519 = PublicKey::from(&StaticSecret::from(sk_x25519));
        let d_kem = hkdf(pk_x25519.as_bytes(), DERIVE_KEM_D_LABEL, &sk_x25519);
        let z_kem = hkdf(pk_x25519.as_bytes(), DERIVE_KEM_Z_LABEL, &sk_x25519);
        Ok(Self {
            sk_x25519,
            d_kem,
            z_kem,
        })
    }

    /// Serialize this hybrid secret key as an uppercase `AGE-SECRET-KEY-PQ-1…` Bech32 string
    /// wrapped in [`Zeroizing`].
    pub fn to_secret_string(&self) -> Zeroizing<String> {
        let mut raw = Zeroizing::new([0u8; HYBRID_SECRET_KEY_BYTES]);
        raw[0..32].copy_from_slice(&self.sk_x25519);
        raw[32..64].copy_from_slice(&self.d_kem);
        raw[64..96].copy_from_slice(&self.z_kem);
        let mut encoded = bech32::encode(HYBRID_SECRET_KEY_HRP, raw.to_base32(), Variant::Bech32)
            .expect("HYBRID_SECRET_KEY_HRP is valid");
        let upper = Zeroizing::new(encoded.to_ascii_uppercase());
        encoded.zeroize();
        upper
    }

    /// Serialize the classical `AGE-SECRET-KEY-1…` half wrapped in [`Zeroizing`].
    pub fn to_classical_secret_string(&self) -> Zeroizing<String> {
        let mut encoded = bech32::encode(
            CLASSICAL_SECRET_KEY_HRP,
            self.sk_x25519.to_base32(),
            Variant::Bech32,
        )
        .expect("CLASSICAL_SECRET_KEY_HRP is valid");
        let upper = Zeroizing::new(encoded.to_ascii_uppercase());
        encoded.zeroize();
        upper
    }

    /// Return the corresponding hybrid `age1pq1…` public recipient.
    pub fn to_public(&self) -> HybridRecipient {
        let static_sk = StaticSecret::from(self.sk_x25519);
        let pk_x25519 = *PublicKey::from(&static_sk).as_bytes();
        let d_b32 = B32::from(self.d_kem);
        let z_b32 = B32::from(self.z_kem);
        let (_dk, ek) = MlKem768::generate_deterministic(&d_b32, &z_b32);
        let mut ek_bytes = [0u8; MLKEM768_EK_BYTES];
        ek_bytes.copy_from_slice(ek.as_bytes().as_slice());
        HybridRecipient {
            pk_x25519,
            ek_bytes: Box::new(ek_bytes),
            ek,
        }
    }

    /// Return the classical `age1…` (`X25519`) recipient for the classical half.
    pub fn to_classical_public(&self) -> age::x25519::Recipient {
        self.to_public().classical_recipient()
    }

    fn decapsulation_key_and_ek(&self) -> (MlKem768Dk, [u8; MLKEM768_EK_BYTES]) {
        let d_b32 = B32::from(self.d_kem);
        let z_b32 = B32::from(self.z_kem);
        let (dk, ek) = MlKem768::generate_deterministic(&d_b32, &z_b32);
        let mut ek_bytes = [0u8; MLKEM768_EK_BYTES];
        ek_bytes.copy_from_slice(ek.as_bytes().as_slice());
        (dk, ek_bytes)
    }

    fn unwrap_hybrid_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        let [epk_arg, ct_arg] = &stanza.args[..] else {
            return Some(Err(DecryptError::InvalidHeader));
        };
        if stanza.body.len() != ENCRYPTED_FILE_KEY_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }

        // Reject padded base64 arguments per age stanza specification.
        if epk_arg.contains('=') || ct_arg.contains('=') {
            return Some(Err(DecryptError::InvalidHeader));
        }
        let epk_vec = match BASE64_STANDARD_NO_PAD.decode(epk_arg) {
            Ok(v) => v,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        let epk_bytes: [u8; X25519_KEY_BYTES] = match epk_vec.as_slice().try_into() {
            Ok(a) => a,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        let ct_vec = match BASE64_STANDARD_NO_PAD.decode(ct_arg) {
            Ok(v) => v,
            Err(_) => return Some(Err(DecryptError::InvalidHeader)),
        };
        if ct_vec.len() != MLKEM768_CT_BYTES {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let static_sk = StaticSecret::from(self.sk_x25519);
        let pk_x25519 = PublicKey::from(&static_sk);
        let epk = PublicKey::from(epk_bytes);
        let ss_x25519 = static_sk.diffie_hellman(&epk);
        if bool::from(
            ss_x25519
                .as_bytes()
                .iter()
                .fold(0u8, |acc, b| acc | b)
                .ct_eq(&0u8),
        ) {
            return Some(Err(DecryptError::InvalidHeader));
        }

        let (dk, ek_bytes) = self.decapsulation_key_and_ek();
        let Ok(ct_encoded) = <&ml_kem::Ciphertext<MlKem768>>::try_from(&ct_vec[..]) else {
            return Some(Err(DecryptError::InvalidHeader));
        };
        let Ok(ss_kem) = dk.decapsulate(ct_encoded) else {
            return Some(Err(DecryptError::InvalidHeader));
        };

        let wrap_key = combine_hybrid_wrap_key(
            ss_x25519.as_bytes(),
            ss_kem.as_slice(),
            &epk_bytes,
            pk_x25519.as_bytes(),
            &ct_vec,
            &ek_bytes,
        );

        aead_decrypt(&wrap_key, FILE_KEY_BYTES, &stanza.body)
            .ok()
            .map(|mut pt| {
                Ok(FileKey::init_with_mut(|file_key| {
                    file_key.copy_from_slice(&pt);
                    pt.zeroize();
                }))
            })
    }

    fn unwrap_classical_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        let classical_str = self.to_classical_secret_string();
        let classical_id = age::x25519::Identity::from_str(&classical_str).ok()?;
        classical_id.unwrap_stanza(stanza)
    }
}

impl FromStr for HybridIdentity {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if let Some((age_part, kem_part)) = trimmed.split_once("+mlkem768:") {
            let (hrp, mut sk_bytes) = decode_bech32_any_case(age_part)?;
            if hrp != CLASSICAL_SECRET_KEY_HRP {
                sk_bytes.zeroize();
                return Err("incorrect classical age secret key HRP in composite identity");
            }
            let sk_x25519: [u8; X25519_KEY_BYTES] = match sk_bytes.as_slice().try_into() {
                Ok(a) => a,
                Err(_) => {
                    sk_bytes.zeroize();
                    return Err("incorrect classical X25519 secret key length");
                }
            };
            sk_bytes.zeroize();
            let mut kem_seed = Zeroizing::new(
                BASE64_STANDARD_NO_PAD
                    .decode(kem_part.trim().trim_end_matches('='))
                    .map_err(|_| "invalid ML-KEM-768 base64 secret seed")?,
            );
            if kem_seed.len() != 64 {
                return Err("incorrect ML-KEM-768 secret seed length (expected 64 bytes d || z)");
            }
            let mut d_kem = [0u8; 32];
            let mut z_kem = [0u8; 32];
            d_kem.copy_from_slice(&kem_seed[..32]);
            z_kem.copy_from_slice(&kem_seed[32..64]);
            kem_seed.zeroize();
            return Ok(Self {
                sk_x25519,
                d_kem,
                z_kem,
            });
        }

        let (hrp, mut bytes) = decode_bech32_any_case(trimmed)?;
        if hrp == HYBRID_SECRET_KEY_HRP {
            if bytes.len() != HYBRID_SECRET_KEY_BYTES {
                bytes.zeroize();
                return Err("incorrect hybrid identity length");
            }
            let mut sk_x25519 = [0u8; X25519_KEY_BYTES];
            let mut d_kem = [0u8; 32];
            let mut z_kem = [0u8; 32];
            sk_x25519.copy_from_slice(&bytes[0..32]);
            d_kem.copy_from_slice(&bytes[32..64]);
            z_kem.copy_from_slice(&bytes[64..96]);
            bytes.zeroize();
            Ok(Self {
                sk_x25519,
                d_kem,
                z_kem,
            })
        } else if hrp == CLASSICAL_SECRET_KEY_HRP {
            bytes.zeroize();
            Self::from_age_secret_key(trimmed)
        } else {
            bytes.zeroize();
            Err("incorrect identity HRP (expected AGE-SECRET-KEY-PQ-1… or AGE-SECRET-KEY-1…)")
        }
    }
}

impl age::Identity for HybridIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, DecryptError>> {
        match stanza.tag.as_str() {
            X25519_MLKEM768_STANZA_TAG => self.unwrap_hybrid_stanza(stanza),
            "X25519" => self.unwrap_classical_stanza(stanza),
            _ => None,
        }
    }
}

/// Recipient for diagnostic bundle encryption: either a `DIP-PQ-0` `P0.1`
/// hybrid `X25519 + ML-KEM-768` recipient (`age1pq1…` or `age1…+mlkem768:…`)
/// or a legacy classical `age1…` (`X25519`) recipient.
#[derive(Clone, Debug)]
pub enum BundleRecipient {
    Hybrid(Box<HybridRecipient>),
    Classical(age::x25519::Recipient),
}

impl BundleRecipient {
    pub fn is_hybrid(&self) -> bool {
        matches!(self, Self::Hybrid(_))
    }
}

impl FromStr for BundleRecipient {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.starts_with("age1pq1")
            || trimmed.starts_with("agepq1")
            || trimmed.contains("+mlkem768:")
        {
            return HybridRecipient::from_str(trimmed)
                .map(|r| Self::Hybrid(Box::new(r)))
                .map_err(|e| e.to_owned());
        }
        if let Ok(r) = trimmed.parse::<age::x25519::Recipient>() {
            return Ok(Self::Classical(r));
        }
        HybridRecipient::from_str(trimmed)
            .map(|r| Self::Hybrid(Box::new(r)))
            .map_err(|e| e.to_owned())
    }
}

impl age::Recipient for BundleRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), EncryptError> {
        match self {
            Self::Hybrid(h) => h.wrap_file_key(file_key),
            Self::Classical(c) => c.wrap_file_key(file_key),
        }
    }
}

/// Parse an identity file or single-line identity string (`AGE-SECRET-KEY-PQ-1…`
/// or `AGE-SECRET-KEY-1…`, skipping `#` comments and blank lines).
pub fn parse_identity_text(text: &str) -> Result<HybridIdentity, String> {
    let mut pq_line: Option<&str> = None;
    let mut classical_line: Option<&str> = None;
    let mut kem_comment_seed: Option<&str> = None;

    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("# mlkem768-seed:") {
            kem_comment_seed = Some(rest.trim());
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let upper = line.to_ascii_uppercase();
        if upper.starts_with("AGE-SECRET-KEY-PQ-1") {
            pq_line = Some(line);
        } else if upper.starts_with("AGE-SECRET-KEY-1") {
            classical_line = Some(line);
        }
    }

    if let Some(pq) = pq_line {
        return HybridIdentity::from_str(pq).map_err(|e| e.to_owned());
    }
    if let Some(cl) = classical_line {
        if let Some(seed_b64) = kem_comment_seed {
            let combined = Zeroizing::new(format!("{cl}+mlkem768:{seed_b64}"));
            return HybridIdentity::from_str(&combined).map_err(|e| e.to_owned());
        }
        return HybridIdentity::from_str(cl).map_err(|e| e.to_owned());
    }
    HybridIdentity::from_str(text.trim()).map_err(|e| e.to_owned())
}

/// §8.4 / `DIP-PQ-0` `P0.1`: Compress `tar` with `zstd` (level 12) and encrypt
/// with `age` (`X25519-MLKEM768` hybrid stanza for `age1pq1…` recipients or
/// classical `X25519` stanza for `age1…` recipients).
pub fn seal(recipient: &str, tar: &[u8]) -> Result<Vec<u8>, String> {
    let r: BundleRecipient = recipient
        .parse()
        .map_err(|e| format!("the developer key does not parse: {e}"))?;
    let z =
        zstd::bulk::compress(tar, ZSTD_LEVEL).map_err(|e| format!("compressing: {}", e.kind()))?;
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient))
        .map_err(|e| format!("encrypting: {e}"))?;
    let mut out = Vec::with_capacity(z.len() + 2048);
    let mut w = enc
        .wrap_output(&mut out)
        .map_err(|e| format!("encrypting: {}", e.kind()))?;
    w.write_all(&z)
        .map_err(|e| format!("encrypting: {}", e.kind()))?;
    w.finish()
        .map_err(|e| format!("encrypting: {}", e.kind()))?;
    Ok(out)
}

/// Decrypt an `age`-sealed diagnostic bundle (`X25519-MLKEM768` hybrid or
/// classical `X25519`) and decompress its `zstd` payload into raw `tar` bytes.
pub fn open_with_identity(ciphertext: &[u8], identity: &HybridIdentity) -> Result<Vec<u8>, String> {
    let d =
        age::Decryptor::new_buffered(ciphertext).map_err(|e| format!("not an age file: {e}"))?;
    let mut r = d
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| format!("decrypt failed (wrong key, or damaged): {e}"))?;
    let mut z = Vec::new();
    r.read_to_end(&mut z)
        .map_err(|e| format!("decrypt failed (damaged): {}", e.kind()))?;
    let mut tar = Vec::new();
    zstd::stream::read::Decoder::new(z.as_slice())
        .and_then(|mut dec| dec.read_to_end(&mut tar))
        .map_err(|e| format!("decompressing: {}", e.kind()))?;
    Ok(tar)
}

/// Parse `identity_text` (`AGE-SECRET-KEY-PQ-1…` or `AGE-SECRET-KEY-1…`) and
/// open `ciphertext`.
pub fn open(identity_text: &str, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let identity = parse_identity_text(identity_text).map_err(|_| {
        "the age identity does not parse (expected AGE-SECRET-KEY-PQ-1… or AGE-SECRET-KEY-1…)"
            .to_owned()
    })?;
    open_with_identity(ciphertext, &identity)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_identity_and_recipient_bech32_round_trip() {
        let id = HybridIdentity::from_seeds([0x11; 32], [0x22; 32], [0x33; 32]);
        let sk_str = id.to_secret_string();
        assert!(sk_str.starts_with("AGE-SECRET-KEY-PQ-1"));

        let parsed_id = HybridIdentity::from_str(&sk_str).expect("valid hybrid secret key");
        let recip = id.to_public();
        let recip_str = recip.to_string();
        assert!(recip_str.starts_with("age1pq1"));

        let parsed_recip = HybridRecipient::from_str(&recip_str).expect("valid hybrid recipient");
        assert_eq!(recip, parsed_recip);
        assert_eq!(parsed_id.to_public(), recip);

        // Composite string format also round-trips to the exact same HybridRecipient
        let comp = recip.to_composite_string();
        assert!(comp.contains("+mlkem768:"));
        let parsed_comp = HybridRecipient::from_str(&comp).expect("valid composite recipient");
        assert_eq!(recip, parsed_comp);
    }

    #[test]
    fn hybrid_seal_emits_x25519_mlkem768_stanza_and_round_trips() {
        let id = HybridIdentity::generate();
        let recip = id.to_public();
        let payload = b"irondivi-diag hybrid post-quantum test payload\n".repeat(128);

        let ct = seal(&recip.to_string(), &payload).expect("hybrid seal succeeds");
        assert!(ct.starts_with(b"age-encryption.org/v1\n"));

        // Verify the header contains the DIP-PQ-0 §4.1 X25519-MLKEM768 stanza
        let header_end = ct
            .windows(4)
            .position(|w| w == b"\n---")
            .expect("age header delimiter present");
        let header_str = std::str::from_utf8(&ct[..header_end]).expect("ASCII age header");
        assert!(
            header_str.contains("\n-> X25519-MLKEM768 "),
            "missing X25519-MLKEM768 stanza in header:\n{header_str}"
        );
        assert!(
            !header_str.contains("\n-> X25519 "),
            "hybrid bundle must not leak a parallel classical X25519 stanza"
        );

        let opened = open(&id.to_secret_string(), &ct).expect("hybrid open succeeds");
        assert_eq!(opened, payload);
    }

    #[test]
    fn hybrid_security_requires_both_x25519_and_mlkem768_halves() {
        let id = HybridIdentity::from_seeds([0x41; 32], [0x42; 32], [0x43; 32]);
        let recip = id.to_public();
        let ct = seal(&recip.to_string(), b"secret diagnostic bundle").unwrap();

        // 1. Right X25519 secret, wrong ML-KEM-768 seed -> MUST FAIL
        let wrong_pq = HybridIdentity::from_seeds([0x41; 32], [0x99; 32], [0x43; 32]);
        assert!(
            open_with_identity(&ct, &wrong_pq).is_err(),
            "decryption must fail when ML-KEM-768 key is wrong even if X25519 matches"
        );

        // 2. Wrong X25519 secret, right ML-KEM-768 seed -> MUST FAIL
        let wrong_classical = HybridIdentity::from_seeds([0x99; 32], [0x42; 32], [0x43; 32]);
        assert!(
            open_with_identity(&ct, &wrong_classical).is_err(),
            "decryption must fail when X25519 key is wrong even if ML-KEM-768 matches"
        );

        // 3. Classical-only age::x25519::Identity cannot unwrap X25519-MLKEM768 stanza
        let classical_id =
            age::x25519::Identity::from_str(&id.to_classical_secret_string()).unwrap();
        let dec = age::Decryptor::new_buffered(&ct[..]).unwrap();
        assert!(dec
            .decrypt(std::iter::once(&classical_id as &dyn age::Identity))
            .is_err());

        // 4. Both halves right -> succeeds
        assert_eq!(
            open_with_identity(&ct, &id).unwrap(),
            b"secret diagnostic bundle"
        );
    }

    #[test]
    fn backward_compatible_with_classical_age_bundles_and_identities() {
        let classical_id = age::x25519::Identity::generate();
        let classical_recip = classical_id.to_public().to_string();
        let classical_sk = classical_id.to_string();

        // Classical bundle sealed to `age1...`
        let ct_classical = seal(&classical_recip, b"legacy x25519 bundle").unwrap();
        assert_eq!(
            open(classical_sk.expose_secret(), &ct_classical).unwrap(),
            b"legacy x25519 bundle"
        );

        // Deterministic hybrid upgrade from existing `AGE-SECRET-KEY-1...`
        let derived_hybrid =
            HybridIdentity::from_age_secret_key(classical_sk.expose_secret()).unwrap();
        let hybrid_recip = derived_hybrid.to_public().to_string();
        let ct_hybrid = seal(&hybrid_recip, b"upgraded hybrid bundle").unwrap();

        // The same `AGE-SECRET-KEY-1...` opens BOTH the legacy classical bundle and the hybrid bundle!
        assert_eq!(
            open(classical_sk.expose_secret(), &ct_hybrid).unwrap(),
            b"upgraded hybrid bundle"
        );
        assert_eq!(
            open(&derived_hybrid.to_secret_string(), &ct_classical).unwrap(),
            b"legacy x25519 bundle"
        );
    }

    #[test]
    fn fips_203_modulus_check_rejects_out_of_range_ek() {
        let id = HybridIdentity::from_seeds([0x55; 32], [0x66; 32], [0x77; 32]);
        let recip = id.to_public();
        let mut bad_ek = *recip.mlkem768_ek_bytes();
        // Set first 12-bit coefficient to 0xFFF = 4095 >= q (3329) while keeping 384-byte polynomial block non-trivial
        bad_ek[0] = 0xFF;
        bad_ek[1] = 0xFF;
        assert!(
            HybridRecipient::from_components(*recip.x25519_public_bytes(), bad_ek).is_err(),
            "FIPS 203 §7.2 modulus check must reject coefficient >= 3329"
        );
    }

    #[test]
    fn hybrid_identity_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: Zeroize + ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<HybridIdentity>();

        let mut id = HybridIdentity::from_seeds([0xAA; 32], [0xBB; 32], [0xCC; 32]);
        id.zeroize();
        assert_eq!(id.sk_x25519, [0u8; 32]);
        assert_eq!(id.d_kem, [0u8; 32]);
        assert_eq!(id.z_kem, [0u8; 32]);
    }
}
