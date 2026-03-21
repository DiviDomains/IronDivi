// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! BIP38 Integration Tests
//!
//! Demonstrates end-to-end usage of BIP38 encryption/decryption

use divi_crypto::{bip38_decrypt, bip38_encrypt, SecretKey};

#[test]
fn test_bip38_paper_wallet_workflow() {
    // 1. Generate a new private key (as if creating a paper wallet)
    let secret = SecretKey::new_random();
    let private_key_bytes = secret.as_bytes();
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(private_key_bytes);

    // 2. User provides a strong passphrase
    let passphrase = "MySecurePassphrase123!";

    // 3. Encrypt the private key for paper wallet storage
    let encrypted = bip38_encrypt(&key_array, passphrase, true).unwrap();

    println!("Encrypted BIP38 key: {}", encrypted);
    assert!(
        encrypted.starts_with("6P"),
        "BIP38 keys should start with 6P"
    );

    // 4. Later, user wants to import the paper wallet
    let (decrypted_key, compressed) = bip38_decrypt(&encrypted, passphrase).unwrap();

    // 5. Verify the decrypted key matches the original
    assert_eq!(key_array, decrypted_key);
    assert!(compressed);

    // 6. Reconstruct the keypair
    let recovered_secret = SecretKey::from_bytes(&decrypted_key).unwrap();
    assert_eq!(secret.as_bytes(), recovered_secret.as_bytes());
}

#[test]
fn test_bip38_different_passphrases() {
    let private_key = [0x42; 32];

    // Encrypt with passphrase A
    let encrypted_a = bip38_encrypt(&private_key, "password_a", true).unwrap();

    // Encrypt with passphrase B - should produce different ciphertext
    let encrypted_b = bip38_encrypt(&private_key, "password_b", true).unwrap();

    assert_ne!(
        encrypted_a, encrypted_b,
        "Different passphrases should produce different ciphertexts"
    );

    // Each can be decrypted with its own passphrase
    let (decrypted_a, _) = bip38_decrypt(&encrypted_a, "password_a").unwrap();
    let (decrypted_b, _) = bip38_decrypt(&encrypted_b, "password_b").unwrap();

    assert_eq!(private_key, decrypted_a);
    assert_eq!(private_key, decrypted_b);

    // Cross-decryption should fail
    assert!(bip38_decrypt(&encrypted_a, "password_b").is_err());
    assert!(bip38_decrypt(&encrypted_b, "password_a").is_err());
}

#[test]
fn test_bip38_compressed_vs_uncompressed() {
    let private_key = [0x33; 32];
    let passphrase = "test";

    // Encrypt in both formats
    let encrypted_compressed = bip38_encrypt(&private_key, passphrase, true).unwrap();
    let encrypted_uncompressed = bip38_encrypt(&private_key, passphrase, false).unwrap();

    // They should be different
    assert_ne!(encrypted_compressed, encrypted_uncompressed);

    // Decrypt and verify compression flags
    let (key_c, compressed_c) = bip38_decrypt(&encrypted_compressed, passphrase).unwrap();
    let (key_u, compressed_u) = bip38_decrypt(&encrypted_uncompressed, passphrase).unwrap();

    assert_eq!(private_key, key_c);
    assert_eq!(private_key, key_u);
    assert!(compressed_c);
    assert!(!compressed_u);
}
