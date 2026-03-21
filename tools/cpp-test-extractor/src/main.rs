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

//! C++ Test Vector Extractor
//!
//! Extracts test vectors from the C++ Divi codebase for use in Rust tests.
//! This ensures byte-perfect compatibility between implementations.

use clap::Parser;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Parser, Debug)]
#[command(name = "cpp-test-extractor")]
#[command(about = "Extract test vectors from C++ Divi codebase")]
struct Args {
    /// Path to C++ Divi source directory
    #[arg(short, long)]
    source: PathBuf,

    /// Output directory for test vectors
    #[arg(short, long, default_value = "../../tests/consensus-vectors")]
    output: PathBuf,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// A test vector extracted from C++ code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestVector {
    /// Name/description of the test
    pub name: String,
    /// Source file where this was found
    pub source_file: String,
    /// Line number in source
    pub line_number: usize,
    /// Category (hash, signature, block, transaction, etc.)
    pub category: String,
    /// Input data (hex encoded)
    pub input_hex: String,
    /// Expected output (hex encoded)
    pub expected_hex: String,
    /// Additional context/parameters
    pub params: HashMap<String, String>,
}

/// Collection of test vectors by category
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TestVectorCollection {
    pub hash_vectors: Vec<TestVector>,
    pub signature_vectors: Vec<TestVector>,
    pub block_vectors: Vec<TestVector>,
    pub transaction_vectors: Vec<TestVector>,
    pub script_vectors: Vec<TestVector>,
    pub stake_modifier_vectors: Vec<TestVector>,
    pub kernel_hash_vectors: Vec<TestVector>,
}

fn main() {
    let args = Args::parse();

    println!("C++ Test Vector Extractor");
    println!("=========================");
    println!("Source directory: {}", args.source.display());
    println!("Output directory: {}", args.output.display());
    println!();

    if !args.source.exists() {
        eprintln!(
            "Error: Source directory does not exist: {}",
            args.source.display()
        );
        eprintln!();
        eprintln!("Usage: cpp-test-extractor --source /path/to/divi-cpp");
        eprintln!();
        eprintln!("This tool extracts test vectors from the C++ Divi codebase.");
        eprintln!("You need to provide the path to the C++ source directory.");
        std::process::exit(1);
    }

    let mut collection = TestVectorCollection::default();

    // Find all test files
    let test_files = find_test_files(&args.source);
    println!("Found {} test files", test_files.len());

    for file in &test_files {
        if args.verbose {
            println!("Processing: {}", file.display());
        }

        if let Ok(content) = fs::read_to_string(file) {
            extract_vectors_from_file(&content, file, &mut collection);
        }
    }

    // Print summary
    println!();
    println!("Extracted vectors:");
    println!("  Hash vectors: {}", collection.hash_vectors.len());
    println!(
        "  Signature vectors: {}",
        collection.signature_vectors.len()
    );
    println!("  Block vectors: {}", collection.block_vectors.len());
    println!(
        "  Transaction vectors: {}",
        collection.transaction_vectors.len()
    );
    println!("  Script vectors: {}", collection.script_vectors.len());
    println!(
        "  Stake modifier vectors: {}",
        collection.stake_modifier_vectors.len()
    );
    println!(
        "  Kernel hash vectors: {}",
        collection.kernel_hash_vectors.len()
    );

    // Create output directory
    fs::create_dir_all(&args.output).expect("Failed to create output directory");

    // Write vectors to files
    write_vectors(&args.output, &collection);

    println!();
    println!("Test vectors written to: {}", args.output.display());
}

fn find_test_files(source_dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();

    for entry in WalkDir::new(source_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            // Look for test files and relevant source files
            if name.ends_with("_tests.cpp")
                || name.ends_with("_test.cpp")
                || name.contains("test")
                || name == "hash.cpp"
                || name == "script.cpp"
                || name == "ProofOfStakeCalculator.cpp"
                || name == "PoSStakeModifierService.cpp"
            {
                files.push(path.to_path_buf());
            }
        }
    }

    files
}

fn extract_vectors_from_file(content: &str, file: &Path, collection: &mut TestVectorCollection) {
    let file_name = file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Extract hash test vectors
    extract_hash_vectors(content, &file_name, collection);

    // Extract signature test vectors
    extract_signature_vectors(content, &file_name, collection);

    // Extract block test vectors
    extract_block_vectors(content, &file_name, collection);

    // Extract transaction test vectors
    extract_transaction_vectors(content, &file_name, collection);

    // Extract script test vectors
    extract_script_vectors(content, &file_name, collection);

    // Extract stake modifier vectors
    extract_stake_modifier_vectors(content, &file_name, collection);
}

fn extract_hash_vectors(content: &str, file_name: &str, collection: &mut TestVectorCollection) {
    // Pattern: BOOST_CHECK_EQUAL(Hash(ParseHex("...")), uint256S("..."))
    let hash_re = Regex::new(
        r#"(?i)Hash\s*\(\s*ParseHex\s*\(\s*"([0-9a-fA-F]+)"\s*\)\s*\).*?uint256S?\s*\(\s*"([0-9a-fA-F]+)"\s*\)"#
    ).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if let Some(caps) = hash_re.captures(line) {
            collection.hash_vectors.push(TestVector {
                name: format!("hash_vector_{}", collection.hash_vectors.len()),
                source_file: file_name.to_string(),
                line_number: line_num + 1,
                category: "hash".to_string(),
                input_hex: caps[1].to_string(),
                expected_hex: caps[2].to_string(),
                params: HashMap::new(),
            });
        }
    }
}

fn extract_signature_vectors(
    content: &str,
    file_name: &str,
    collection: &mut TestVectorCollection,
) {
    // Pattern for signature verification tests
    let sig_re =
        Regex::new(r#"(?i)(?:Verify|CheckSig).*?"([0-9a-fA-F]+)".*?"([0-9a-fA-F]+)""#).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if let Some(caps) = sig_re.captures(line) {
            collection.signature_vectors.push(TestVector {
                name: format!("sig_vector_{}", collection.signature_vectors.len()),
                source_file: file_name.to_string(),
                line_number: line_num + 1,
                category: "signature".to_string(),
                input_hex: caps[1].to_string(),
                expected_hex: caps[2].to_string(),
                params: HashMap::new(),
            });
        }
    }
}

fn extract_block_vectors(content: &str, file_name: &str, collection: &mut TestVectorCollection) {
    // Pattern for block hash tests
    let block_re =
        Regex::new(r#"(?i)(?:block|header).*?(?:hash|GetHash).*?"([0-9a-fA-F]{64})""#).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if let Some(caps) = block_re.captures(line) {
            collection.block_vectors.push(TestVector {
                name: format!("block_vector_{}", collection.block_vectors.len()),
                source_file: file_name.to_string(),
                line_number: line_num + 1,
                category: "block".to_string(),
                input_hex: String::new(),
                expected_hex: caps[1].to_string(),
                params: HashMap::new(),
            });
        }
    }
}

fn extract_transaction_vectors(
    content: &str,
    file_name: &str,
    collection: &mut TestVectorCollection,
) {
    // Pattern for transaction tests with hex data
    let tx_re =
        Regex::new(r#"(?i)(?:tx|transaction).*?(?:ParseHex|FromHex).*?"([0-9a-fA-F]+)""#).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if let Some(caps) = tx_re.captures(line) {
            if caps[1].len() > 20 {
                // Only meaningful tx data
                collection.transaction_vectors.push(TestVector {
                    name: format!("tx_vector_{}", collection.transaction_vectors.len()),
                    source_file: file_name.to_string(),
                    line_number: line_num + 1,
                    category: "transaction".to_string(),
                    input_hex: caps[1].to_string(),
                    expected_hex: String::new(),
                    params: HashMap::new(),
                });
            }
        }
    }
}

fn extract_script_vectors(content: &str, file_name: &str, collection: &mut TestVectorCollection) {
    // Pattern for script tests
    let script_re = Regex::new(r#"(?i)(?:script|OP_).*?"([0-9a-fA-F]+)""#).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if let Some(caps) = script_re.captures(line) {
            collection.script_vectors.push(TestVector {
                name: format!("script_vector_{}", collection.script_vectors.len()),
                source_file: file_name.to_string(),
                line_number: line_num + 1,
                category: "script".to_string(),
                input_hex: caps[1].to_string(),
                expected_hex: String::new(),
                params: HashMap::new(),
            });
        }
    }
}

fn extract_stake_modifier_vectors(
    content: &str,
    file_name: &str,
    collection: &mut TestVectorCollection,
) {
    // Pattern for stake modifier calculations
    let stake_re = Regex::new(r#"(?i)stake.*?modifier.*?([0-9a-fA-F]+)"#).unwrap();

    for (line_num, line) in content.lines().enumerate() {
        if let Some(caps) = stake_re.captures(line) {
            collection.stake_modifier_vectors.push(TestVector {
                name: format!("stake_modifier_{}", collection.stake_modifier_vectors.len()),
                source_file: file_name.to_string(),
                line_number: line_num + 1,
                category: "stake_modifier".to_string(),
                input_hex: String::new(),
                expected_hex: caps[1].to_string(),
                params: HashMap::new(),
            });
        }
    }
}

fn write_vectors(output_dir: &Path, collection: &TestVectorCollection) {
    // Write each category to its own file
    let categories = [
        ("hash_vectors.json", &collection.hash_vectors),
        ("signature_vectors.json", &collection.signature_vectors),
        ("block_vectors.json", &collection.block_vectors),
        ("transaction_vectors.json", &collection.transaction_vectors),
        ("script_vectors.json", &collection.script_vectors),
        (
            "stake_modifier_vectors.json",
            &collection.stake_modifier_vectors,
        ),
        ("kernel_hash_vectors.json", &collection.kernel_hash_vectors),
    ];

    for (filename, vectors) in categories {
        let path = output_dir.join(filename);
        let json = serde_json::to_string_pretty(vectors).expect("Failed to serialize");
        fs::write(&path, json).expect("Failed to write file");
    }

    // Write combined file
    let combined_path = output_dir.join("all_vectors.json");
    let json = serde_json::to_string_pretty(collection).expect("Failed to serialize");
    fs::write(combined_path, json).expect("Failed to write file");
}
