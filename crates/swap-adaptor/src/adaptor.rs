// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! ECDSA adaptor (encrypted) signatures over secp256k1, via `ecdsa_fun`.
//!
//! `Tx_refund`/`Tx_punish`/`Tx_redeem` in `xmr-design.md`'s `## Protocol` each need one
//! party's signature encrypted under a public point (`encryption_key`) instead of produced
//! directly: the other party completes it later, and completing it is exactly what reveals
//! the corresponding `decryption_key` to whoever holds the finished on-chain signature. This
//! module is the DIVI-chain-agnostic half of that; [`crate::dleq`] is what ties
//! `decryption_key` to a Monero spend-key share.

pub use ecdsa_fun::adaptor::EncryptedSignature;
pub use ecdsa_fun::fun::{Point, Scalar};
pub use ecdsa_fun::Signature;

use ecdsa_fun::adaptor::{Adaptor as EcdsaAdaptor, HashTranscript};
use ecdsa_fun::fun::nonce;
use rand::rngs::ThreadRng;
use rand_chacha::ChaCha20Rng;
use sha2::Sha256;

type NonceGen = nonce::Synthetic<Sha256, nonce::GlobalRng<ThreadRng>>;
type Transcript = HashTranscript<Sha256, ChaCha20Rng>;

/// Encrypts, verifies, decrypts, and extracts the decryption key from ECDSA adaptor
/// signatures. Thin wrapper over `ecdsa_fun::adaptor::Adaptor` so callers outside this
/// crate don't need to name its transcript/nonce-generator type parameters.
#[derive(Default)]
pub struct AdaptorSigner {
    inner: EcdsaAdaptor<Transcript, NonceGen>,
}

impl AdaptorSigner {
    /// New signer with synthetic (RNG + hash) nonces — `ecdsa_fun`'s recommended default,
    /// safer under RNG failure than pure-deterministic nonces for this adaptor construction.
    pub fn new() -> Self {
        Self::default()
    }

    /// The public key that verifies signatures made with `signing_key`.
    pub fn verification_key_for(&self, signing_key: &Scalar) -> Point {
        self.inner.ecdsa.verification_key_for(signing_key)
    }

    /// The public point under which `decryption_key` encrypts signatures.
    pub fn encryption_key_for(&self, decryption_key: &Scalar) -> Point {
        self.inner.encryption_key_for(decryption_key)
    }

    /// Encrypt a signature over `message_hash` under `encryption_key`. The result verifies
    /// (see [`verify_encrypted_signature`](Self::verify_encrypted_signature)) but cannot be
    /// used on-chain until someone who knows `encryption_key`'s decryption key completes it.
    pub fn encrypted_sign(
        &self,
        signing_key: &Scalar,
        encryption_key: &Point,
        message_hash: &[u8; 32],
    ) -> EncryptedSignature {
        self.inner
            .encrypted_sign(signing_key, encryption_key, message_hash)
    }

    /// Check an encrypted signature without decrypting it: confirms that decrypting with
    /// the right key *would* yield a valid signature over `message_hash` under
    /// `verification_key`, without needing that key.
    #[must_use]
    pub fn verify_encrypted_signature(
        &self,
        verification_key: &Point,
        encryption_key: &Point,
        message_hash: &[u8; 32],
        encrypted: &EncryptedSignature,
    ) -> bool {
        self.inner.verify_encrypted_signature(
            verification_key,
            encryption_key,
            message_hash,
            encrypted,
        )
    }

    /// Complete an encrypted signature into a normal, on-chain-valid ECDSA signature.
    pub fn decrypt_signature(
        &self,
        decryption_key: &Scalar,
        encrypted: EncryptedSignature,
    ) -> Signature {
        self.inner.decrypt_signature(decryption_key, encrypted)
    }

    /// Recover `decryption_key` from a completed signature plus the encrypted signature it
    /// was decrypted from. This is the step that lets the party who *didn't* decrypt it
    /// learn the secret once the completed signature shows up on-chain
    /// (`xmr-design.md`'s `Tx_redeem` step).
    pub fn recover_decryption_key(
        &self,
        encryption_key: &Point,
        signature: &Signature,
        encrypted: &EncryptedSignature,
    ) -> Option<Scalar> {
        self.inner
            .recover_decryption_key(encryption_key, signature, encrypted)
    }

    /// Verify a normal (decrypted) ECDSA signature — what the DIVI side runs once a
    /// `Tx_refund`/`Tx_punish`/`Tx_redeem` signature is actually completed.
    #[must_use]
    pub fn verify(
        &self,
        verification_key: &Point,
        message_hash: &[u8; 32],
        signature: &Signature,
    ) -> bool {
        self.inner
            .ecdsa
            .verify(verification_key, message_hash, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_hash(label: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        Sha256::digest(label).into()
    }

    /// Full happy-path round trip: encrypt, verify-without-decrypting, decrypt, and confirm
    /// the decrypted signature verifies as an ordinary ECDSA signature. Mirrors
    /// `ecdsa_fun`'s own module-level synopsis example.
    #[test]
    fn round_trip_encrypt_verify_decrypt() {
        let adaptor = AdaptorSigner::new();
        let mut rng = rand::thread_rng();

        let signing_key = Scalar::random(&mut rng);
        let verification_key = adaptor.verification_key_for(&signing_key);
        let decryption_key = Scalar::random(&mut rng);
        let encryption_key = adaptor.encryption_key_for(&decryption_key);
        let message_hash = msg_hash(b"divi tx_redeem sighash");

        let encrypted = adaptor.encrypted_sign(&signing_key, &encryption_key, &message_hash);
        assert!(adaptor.verify_encrypted_signature(
            &verification_key,
            &encryption_key,
            &message_hash,
            &encrypted,
        ));

        let signature = adaptor.decrypt_signature(&decryption_key, encrypted);
        assert!(adaptor.verify(&verification_key, &message_hash, &signature));
    }

    /// The whole point of an adaptor signature: completing it on-chain hands anyone who
    /// sees the completed signature the decryption key, even though they never had it.
    #[test]
    fn decrypted_signature_reveals_decryption_key() {
        let adaptor = AdaptorSigner::new();
        let mut rng = rand::thread_rng();

        let signing_key = Scalar::random(&mut rng);
        let decryption_key = Scalar::random(&mut rng);
        let encryption_key = adaptor.encryption_key_for(&decryption_key);
        let message_hash = msg_hash(b"divi tx_punish sighash");

        let encrypted = adaptor.encrypted_sign(&signing_key, &encryption_key, &message_hash);
        let signature = adaptor.decrypt_signature(&decryption_key, encrypted.clone());

        let recovered = adaptor
            .recover_decryption_key(&encryption_key, &signature, &encrypted)
            .expect("completed signature must yield the decryption key");
        assert_eq!(recovered, decryption_key);
    }

    /// An encrypted signature verifies only against the key pair it was actually made
    /// for — swapping in an unrelated verification key must fail.
    #[test]
    fn verify_encrypted_signature_rejects_wrong_verification_key() {
        let adaptor = AdaptorSigner::new();
        let mut rng = rand::thread_rng();

        let signing_key = Scalar::random(&mut rng);
        let wrong_key = Scalar::random(&mut rng);
        let wrong_verification_key = adaptor.verification_key_for(&wrong_key);
        let decryption_key = Scalar::random(&mut rng);
        let encryption_key = adaptor.encryption_key_for(&decryption_key);
        let message_hash = msg_hash(b"divi tx_refund sighash");

        let encrypted = adaptor.encrypted_sign(&signing_key, &encryption_key, &message_hash);
        assert!(!adaptor.verify_encrypted_signature(
            &wrong_verification_key,
            &encryption_key,
            &message_hash,
            &encrypted,
        ));
    }

    /// Recovery must fail (not silently succeed) if the "completed" signature wasn't
    /// actually a decryption of this particular encrypted signature.
    #[test]
    fn recover_decryption_key_fails_for_unrelated_signature() {
        let adaptor = AdaptorSigner::new();
        let mut rng = rand::thread_rng();

        let signing_key = Scalar::random(&mut rng);
        let decryption_key = Scalar::random(&mut rng);
        let encryption_key = adaptor.encryption_key_for(&decryption_key);
        let message_hash = msg_hash(b"divi tx_redeem sighash");
        let encrypted = adaptor.encrypted_sign(&signing_key, &encryption_key, &message_hash);

        // An unrelated, ordinary signature over the same message.
        let unrelated_signature = adaptor.decrypt_signature(
            &Scalar::random(&mut rng),
            adaptor.encrypted_sign(
                &signing_key,
                &adaptor.encryption_key_for(&Scalar::random(&mut rng)),
                &message_hash,
            ),
        );

        assert!(adaptor
            .recover_decryption_key(&encryption_key, &unrelated_signature, &encrypted)
            .is_none());
    }
}
