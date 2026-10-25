// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! `spork-seed <data-dir> <spork-id> <value> <time-signed>`: store a spork in the
//! chain database of an irondivid data directory that is not running, as the
//! node keeps one it accepted.
//!
//! Regtest uses the testnet spork key, whose private key nobody here holds, so
//! no spork can be signed for a regtest node. Divi Core and irondivid load the
//! sporks of their databases without checking them again (spork.cpp
//! `LoadSporksFromDB`), which is how a regtest check gives both kinds the same
//! sporks. The signature stored is only bytes.

use divi_network::SporkMessage;
use divi_storage::ChainDatabase;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!("usage: spork-seed <data-dir> <spork-id> <value> <time-signed>");
        return ExitCode::from(2);
    }
    let (Ok(id), Ok(time)) = (args[2].parse::<i32>(), args[4].parse::<i64>()) else {
        eprintln!("spork-seed: the id and the time are whole numbers");
        return ExitCode::from(2);
    };
    let spork = SporkMessage {
        spork_id: id,
        value: args[3].clone(),
        time_signed: time,
        signature: vec![0x1f; 65],
    };
    let chainstate = std::path::Path::new(&args[1]).join("chainstate");
    if let Err(e) = std::fs::create_dir_all(&chainstate) {
        eprintln!("spork-seed: {e}");
        return ExitCode::FAILURE;
    }
    let result = ChainDatabase::open(&chainstate)
        .and_then(|db| db.put_metadata(format!("spork_{id}").as_bytes(), &spork.serialize()));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("spork-seed: {e}");
            ExitCode::FAILURE
        }
    }
}
