# Consensus Test Vectors

This directory contains test vectors extracted from the C++ Divi codebase
to ensure byte-perfect compatibility between the Rust and C++ implementations.

## Directory Structure

```
consensus-vectors/
├── hash_vectors.json         # Hash function test vectors
├── signature_vectors.json    # ECDSA signature verification vectors
├── block_vectors.json        # Block serialization/hash vectors
├── transaction_vectors.json  # Transaction serialization vectors
├── script_vectors.json       # Script execution test vectors
├── stake_modifier_vectors.json  # PoS stake modifier vectors
├── kernel_hash_vectors.json  # PoS kernel hash vectors
└── all_vectors.json          # Combined test vectors
```

## Generating Test Vectors

Use the `cpp-test-extractor` tool to extract test vectors from the C++ codebase:

```bash
# From workspace root
cargo run -p cpp-test-extractor -- --source /path/to/divi-cpp --output tests/consensus-vectors
```

## Using Test Vectors

Test vectors can be loaded in Rust tests:

```rust
use serde::Deserialize;

#[derive(Deserialize)]
struct TestVector {
    name: String,
    input_hex: String,
    expected_hex: String,
}

#[test]
fn test_hash_vectors() {
    let json = include_str!("consensus-vectors/hash_vectors.json");
    let vectors: Vec<TestVector> = serde_json::from_str(json).unwrap();

    for vector in vectors {
        let input = hex::decode(&vector.input_hex).unwrap();
        let result = hash256(&input);
        assert_eq!(result.to_hex(), vector.expected_hex,
            "Hash mismatch for: {}", vector.name);
    }
}
```

## Validation

The `block-comparator` tool compares block validation results:

```bash
cargo run -p block-comparator -- --blocks mainnet_blocks.json --cpp-results cpp_validation.json
```
