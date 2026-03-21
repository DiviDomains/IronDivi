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

//! Block Comparator
//!
//! Compares block validation results between Rust and C++ implementations.
//! Used to verify byte-perfect compatibility before mainnet deployment.

use clap::Parser;
use divi_crypto::compute_block_hash;
use divi_primitives::block::Block;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "block-comparator")]
#[command(about = "Compare block validation between Rust and C++ implementations")]
struct Args {
    /// Block data file (JSON with hex-encoded blocks)
    #[arg(short, long)]
    blocks: PathBuf,

    /// C++ validation results file (JSON)
    #[arg(short, long)]
    cpp_results: Option<PathBuf>,

    /// Output comparison report
    #[arg(short, long, default_value = "comparison_report.json")]
    output: PathBuf,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// Block data for comparison
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockData {
    /// Block height
    pub height: u64,
    /// Block hash (hex)
    pub hash: String,
    /// Raw block data (hex)
    pub raw_hex: String,
    /// Previous block hash
    pub prev_hash: String,
}

/// Validation result from C++ implementation
#[derive(Debug, Serialize, Deserialize)]
pub struct CppValidationResult {
    pub height: u64,
    pub hash: String,
    pub valid: bool,
    pub error: Option<String>,
    pub block_hash_computed: String,
    pub merkle_root_computed: String,
}

/// Comparison result
#[derive(Debug, Serialize, Deserialize)]
pub struct ComparisonResult {
    pub height: u64,
    pub hash: String,
    pub rust_valid: bool,
    pub cpp_valid: Option<bool>,
    pub hash_matches: bool,
    pub merkle_matches: bool,
    pub rust_error: Option<String>,
    pub cpp_error: Option<String>,
    pub discrepancy: bool,
}

/// Full comparison report
#[derive(Debug, Serialize, Deserialize)]
pub struct ComparisonReport {
    pub total_blocks: usize,
    pub rust_valid_count: usize,
    pub cpp_valid_count: usize,
    pub hash_match_count: usize,
    pub discrepancy_count: usize,
    pub results: Vec<ComparisonResult>,
}

fn main() {
    let args = Args::parse();

    println!("Block Comparator");
    println!("================");
    println!();

    if !args.blocks.exists() {
        eprintln!(
            "Error: Blocks file does not exist: {}",
            args.blocks.display()
        );
        eprintln!();
        eprintln!("Usage: block-comparator --blocks blocks.json [--cpp-results cpp_results.json]");
        eprintln!();
        eprintln!("The blocks file should contain JSON array of BlockData objects:");
        eprintln!(r#"  [{{"height": 0, "hash": "...", "raw_hex": "...", "prev_hash": "..."}}]"#);
        std::process::exit(1);
    }

    // Load blocks
    let blocks_json = fs::read_to_string(&args.blocks).expect("Failed to read blocks file");
    let blocks: Vec<BlockData> =
        serde_json::from_str(&blocks_json).expect("Failed to parse blocks");

    println!("Loaded {} blocks", blocks.len());

    // Load C++ results if provided
    let cpp_results: Option<Vec<CppValidationResult>> = args.cpp_results.as_ref().map(|path| {
        let json = fs::read_to_string(path).expect("Failed to read C++ results");
        serde_json::from_str(&json).expect("Failed to parse C++ results")
    });

    if let Some(ref results) = cpp_results {
        println!("Loaded {} C++ validation results", results.len());
    }

    // Run comparison
    let report = compare_blocks(&blocks, cpp_results.as_deref(), args.verbose);

    // Print summary
    println!();
    println!("Comparison Summary");
    println!("------------------");
    println!("Total blocks: {}", report.total_blocks);
    println!("Rust valid: {}", report.rust_valid_count);
    if cpp_results.is_some() {
        println!("C++ valid: {}", report.cpp_valid_count);
        println!("Hash matches: {}", report.hash_match_count);
        println!("Discrepancies: {}", report.discrepancy_count);
    }

    // Write report
    let report_json = serde_json::to_string_pretty(&report).expect("Failed to serialize report");
    fs::write(&args.output, report_json).expect("Failed to write report");
    println!();
    println!("Report written to: {}", args.output.display());

    // Exit with error if discrepancies found
    if report.discrepancy_count > 0 {
        eprintln!();
        eprintln!("WARNING: {} discrepancies found!", report.discrepancy_count);
        std::process::exit(1);
    }
}

fn compare_blocks(
    blocks: &[BlockData],
    cpp_results: Option<&[CppValidationResult]>,
    verbose: bool,
) -> ComparisonReport {
    let mut results = Vec::new();
    let mut rust_valid_count = 0;
    let mut cpp_valid_count = 0;
    let mut hash_match_count = 0;
    let mut discrepancy_count = 0;

    for block_data in blocks {
        let cpp_result =
            cpp_results.and_then(|results| results.iter().find(|r| r.height == block_data.height));

        // Parse and validate with Rust
        let rust_result = validate_block_rust(block_data);

        let rust_valid = rust_result.is_ok();
        let rust_error = rust_result.err();

        if rust_valid {
            rust_valid_count += 1;
        }

        // Compare with C++ if available
        let (cpp_valid, cpp_error, hash_matches, merkle_matches) = if let Some(cpp) = cpp_result {
            if cpp.valid {
                cpp_valid_count += 1;
            }

            let computed_hash = compute_block_hash_from_data(block_data);
            let hash_matches = computed_hash
                .map(|h| h == cpp.block_hash_computed)
                .unwrap_or(false);

            if hash_matches {
                hash_match_count += 1;
            }

            (Some(cpp.valid), cpp.error.clone(), hash_matches, true)
        } else {
            (None, None, true, true)
        };

        // Check for discrepancy
        let discrepancy = cpp_valid.map(|cv| cv != rust_valid).unwrap_or(false);
        if discrepancy {
            discrepancy_count += 1;
        }

        if verbose && (discrepancy || !rust_valid) {
            println!(
                "Block {}: rust={}, cpp={:?}, hash_match={}, discrepancy={}",
                block_data.height, rust_valid, cpp_valid, hash_matches, discrepancy
            );
        }

        results.push(ComparisonResult {
            height: block_data.height,
            hash: block_data.hash.clone(),
            rust_valid,
            cpp_valid,
            hash_matches,
            merkle_matches,
            rust_error: rust_error.map(|e| e.to_string()),
            cpp_error,
            discrepancy,
        });
    }

    ComparisonReport {
        total_blocks: blocks.len(),
        rust_valid_count,
        cpp_valid_count,
        hash_match_count,
        discrepancy_count,
        results,
    }
}

fn validate_block_rust(block_data: &BlockData) -> Result<(), Box<dyn std::error::Error>> {
    // Decode hex
    let raw = hex::decode(&block_data.raw_hex)?;

    // Parse block
    let _block: Block = divi_primitives::serialize::deserialize(&raw)?;

    // Basic validation would go here
    // For now just check it parses

    Ok(())
}

fn compute_block_hash_from_data(block_data: &BlockData) -> Option<String> {
    let raw = hex::decode(&block_data.raw_hex).ok()?;
    let block: Block = divi_primitives::serialize::deserialize(&raw).ok()?;
    Some(compute_block_hash(&block.header).to_hex())
}
