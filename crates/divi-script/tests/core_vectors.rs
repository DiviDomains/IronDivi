// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Divi Core's own script, signature-hash and transaction test vectors
//! (tests/data/divi-core, from divi/src/test/data at v3.0.0), run the way
//! Divi Core's script_tests.cpp, sighash_tests.cpp and transaction_tests.cpp
//! run them.

use divi_primitives::amount::Amount;
use divi_primitives::hash::Hash256;
use divi_primitives::script::Script;
use divi_primitives::serialize::deserialize;
use divi_primitives::transaction::{OutPoint, Transaction, TxIn, TxOut};
use divi_script::checker::signature_hash;
use divi_script::{verify_script_with_amount, ScriptFlags, TransactionSignatureChecker};
use serde_json::Value;
use std::collections::HashMap;

fn load(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/tests/data/divi-core/{}",
        env!("CARGO_MANIFEST_DIR"),
        name
    );
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

/// Opcode names Core's ParseScript knows: OP_NOP (0x61) through
/// OP_REQUIRE_COINSTAKE (0xb9) in order, OP_RESERVED, and Divi's aliases
fn op_names() -> HashMap<String, u8> {
    const NAMES: [&str; 89] = [
        "OP_NOP",
        "OP_VER",
        "OP_IF",
        "OP_NOTIF",
        "OP_VERIF",
        "OP_VERNOTIF",
        "OP_ELSE",
        "OP_ENDIF",
        "OP_VERIFY",
        "OP_META",
        "OP_TOALTSTACK",
        "OP_FROMALTSTACK",
        "OP_2DROP",
        "OP_2DUP",
        "OP_3DUP",
        "OP_2OVER",
        "OP_2ROT",
        "OP_2SWAP",
        "OP_IFDUP",
        "OP_DEPTH",
        "OP_DROP",
        "OP_DUP",
        "OP_NIP",
        "OP_OVER",
        "OP_PICK",
        "OP_ROLL",
        "OP_ROT",
        "OP_SWAP",
        "OP_TUCK",
        "OP_CAT",
        "OP_SUBSTR",
        "OP_LEFT",
        "OP_RIGHT",
        "OP_SIZE",
        "OP_INVERT",
        "OP_AND",
        "OP_OR",
        "OP_XOR",
        "OP_EQUAL",
        "OP_EQUALVERIFY",
        "OP_RESERVED1",
        "OP_RESERVED2",
        "OP_1ADD",
        "OP_1SUB",
        "OP_2MUL",
        "OP_2DIV",
        "OP_NEGATE",
        "OP_ABS",
        "OP_NOT",
        "OP_0NOTEQUAL",
        "OP_ADD",
        "OP_SUB",
        "OP_MUL",
        "OP_DIV",
        "OP_MOD",
        "OP_LSHIFT",
        "OP_RSHIFT",
        "OP_BOOLAND",
        "OP_BOOLOR",
        "OP_NUMEQUAL",
        "OP_NUMEQUALVERIFY",
        "OP_NUMNOTEQUAL",
        "OP_LESSTHAN",
        "OP_GREATERTHAN",
        "OP_LESSTHANOREQUAL",
        "OP_GREATERTHANOREQUAL",
        "OP_MIN",
        "OP_MAX",
        "OP_WITHIN",
        "OP_RIPEMD160",
        "OP_SHA1",
        "OP_SHA256",
        "OP_HASH160",
        "OP_HASH256",
        "OP_CODESEPARATOR",
        "OP_CHECKSIG",
        "OP_CHECKSIGVERIFY",
        "OP_CHECKMULTISIG",
        "OP_CHECKMULTISIGVERIFY",
        "OP_NOP1",
        "OP_CHECKLOCKTIMEVERIFY",
        "OP_NOP3",
        "OP_NOP4",
        "OP_NOP5",
        "OP_NOP6",
        "OP_NOP7",
        "OP_NOP8",
        "OP_LIMIT_TRANSFER",
        "OP_REQUIRE_COINSTAKE",
    ];
    let mut map = HashMap::new();
    let mut add = |name: &str, op: u8| {
        map.insert(name.to_string(), op);
        map.insert(name.trim_start_matches("OP_").to_string(), op);
    };
    for (i, name) in NAMES.iter().enumerate() {
        add(name, 0x61 + i as u8);
    }
    add("OP_RESERVED", 0x50);
    add("OP_RETURN", 0x6a);
    add("OP_NOP2", 0xb1);
    add("OP_NOP9", 0xb8);
    add("OP_NOP10", 0xb9);
    map
}

/// `CScript() << data`
fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    if data.len() < 0x4c {
        out.push(data.len() as u8);
    } else if data.len() <= 0xff {
        out.push(0x4c);
        out.push(data.len() as u8);
    } else if data.len() <= 0xffff {
        out.push(0x4d);
        out.extend_from_slice(&(data.len() as u16).to_le_bytes());
    } else {
        out.push(0x4e);
        out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Core's `ParseScript` (core_io.cpp)
fn parse_script(s: &str, names: &HashMap<String, u8>) -> Script {
    let mut out = Vec::new();
    for w in s.split([' ', '\t', '\n']).filter(|w| !w.is_empty()) {
        let digits = |x: &str| !x.is_empty() && x.bytes().all(|b| b.is_ascii_digit());
        if digits(w) || (w.starts_with('-') && digits(&w[1..])) {
            // `result << n` (push_int64)
            let n: i64 = w.parse().unwrap();
            if n == -1 || (1..=16).contains(&n) {
                out.push((n + 0x50) as u8);
            } else if n == 0 {
                out.push(0x00);
            } else {
                push_data(&mut out, &divi_script::ScriptNum::new(n).encode());
            }
        } else if w.len() > 2 && w.starts_with("0x") && hex::decode(&w[2..]).is_ok() {
            out.extend(hex::decode(&w[2..]).unwrap());
        } else if w.len() >= 2 && w.starts_with('\'') && w.ends_with('\'') {
            push_data(&mut out, &w.as_bytes()[1..w.len() - 1]);
        } else if let Some(&op) = names.get(w) {
            out.push(op);
        } else {
            panic!("script parse error: {}", w);
        }
    }
    Script::from_bytes(out)
}

/// The flag names Core's tests accept
fn parse_flags(s: &str) -> ScriptFlags {
    let mut flags = ScriptFlags::new();
    for word in s.split(',').filter(|w| !w.is_empty()) {
        flags.set(match word {
            "NONE" => 0,
            "P2SH" => ScriptFlags::P2SH,
            "STRICTENC" => ScriptFlags::STRICTENC,
            "DERSIG" => ScriptFlags::DERSIG,
            "LOW_S" => ScriptFlags::LOW_S,
            "SIGPUSHONLY" => ScriptFlags::SIGPUSHONLY,
            "MINIMALDATA" => ScriptFlags::MINIMALDATA,
            "NULLDUMMY" => ScriptFlags::NULLDUMMY,
            "DISCOURAGE_UPGRADABLE_NOPS" => ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS,
            other => panic!("unknown flag {}", other),
        });
    }
    flags
}

/// Core's script_tests DoTest: a crediting and a spending transaction
fn run_script_test(sig: &Script, spk: &Script, flags: ScriptFlags) -> bool {
    let credit = Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint::null(),
            Script::from_bytes(vec![0x00, 0x00]),
            u32::MAX,
        )],
        vout: vec![TxOut::new(Amount::ZERO, spk.clone())],
        lock_time: 0,
    };
    let spend = Transaction {
        version: 1,
        vin: vec![TxIn::new(
            OutPoint::new(credit.txid(), 0),
            sig.clone(),
            u32::MAX,
        )],
        vout: vec![TxOut::new(Amount::ZERO, Script::new())],
        lock_time: 0,
    };
    let checker = TransactionSignatureChecker::new(&spend, 0, Amount::ZERO);
    verify_script_with_amount(sig, spk, 0, flags, &checker).is_ok()
}

fn script_vectors(name: &str, expect_valid: bool) {
    let names = op_names();
    let mut failures = Vec::new();
    let mut count = 0;
    for t in load(name) {
        let t = t.as_array().unwrap();
        if t.len() < 3 {
            continue;
        }
        let sig = parse_script(t[0].as_str().unwrap(), &names);
        let spk = parse_script(t[1].as_str().unwrap(), &names);
        let flags = parse_flags(t[2].as_str().unwrap());
        count += 1;
        if run_script_test(&sig, &spk, flags) != expect_valid {
            failures.push(serde_json::to_string(t).unwrap());
        }
    }
    assert!(count > 400, "{} vectors read from {}", count, name);
    assert!(
        failures.is_empty(),
        "{} of {} {} vectors disagree with Divi Core:\n{}",
        failures.len(),
        count,
        name,
        failures.join("\n")
    );
}

#[test]
fn divi_core_script_valid() {
    script_vectors("script_valid.json", true);
}

#[test]
fn divi_core_script_invalid() {
    script_vectors("script_invalid.json", false);
}

#[test]
fn divi_core_sighash() {
    let mut failures = Vec::new();
    let mut count = 0;
    for t in load("sighash.json") {
        let t = t.as_array().unwrap();
        if t.len() == 1 {
            continue;
        }
        let tx: Transaction = deserialize(&hex::decode(t[0].as_str().unwrap()).unwrap()).unwrap();
        let script = Script::from_bytes(hex::decode(t[1].as_str().unwrap()).unwrap());
        let n_in = t[2].as_i64().unwrap() as usize;
        let hash_type = t[3].as_i64().unwrap() as i32;
        let expected = t[4].as_str().unwrap();
        let got = Hash256::from_bytes(signature_hash(&script, &tx, n_in, hash_type)).to_hex();
        count += 1;
        if got != expected {
            failures.push(format!(
                "{} (got {})",
                serde_json::to_string(t).unwrap(),
                got
            ));
        }
    }
    assert_eq!(count, 499);
    assert!(
        failures.is_empty(),
        "{} sighash vectors disagree:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// The parts of Core's CheckTransaction that tx_invalid.json exercises
fn check_transaction(tx: &Transaction) -> bool {
    const MAX_MONEY: i64 = 21_000_000_000 * 100_000_000;
    if tx.vin.is_empty() || tx.vout.is_empty() {
        return false;
    }
    let mut total = 0i64;
    for out in &tx.vout {
        let v = out.value.as_sat();
        if !(0..=MAX_MONEY).contains(&v) {
            return false;
        }
        total += v;
        if !(0..=MAX_MONEY).contains(&total) {
            return false;
        }
    }
    let mut seen = std::collections::HashSet::new();
    for input in &tx.vin {
        if !seen.insert((input.prevout.txid, input.prevout.vout)) {
            return false;
        }
    }
    if tx.is_coinbase() {
        let len = tx.vin[0].script_sig.as_bytes().len();
        if !(2..=100).contains(&len) {
            return false;
        }
    } else if tx.vin.iter().any(|i| i.prevout.is_null()) {
        return false;
    }
    true
}

fn tx_vectors(name: &str, expect_valid: bool) {
    let names = op_names();
    let mut failures = Vec::new();
    let mut count = 0;
    for t in load(name) {
        let t = t.as_array().unwrap();
        if !t[0].is_array() {
            continue;
        }
        let mut prevouts = HashMap::new();
        for p in t[0].as_array().unwrap() {
            let p = p.as_array().unwrap();
            let txid = Hash256::from_hex(p[0].as_str().unwrap()).unwrap();
            let vout = p[1].as_i64().unwrap() as u32;
            prevouts.insert((txid, vout), parse_script(p[2].as_str().unwrap(), &names));
        }
        let tx: Transaction = deserialize(&hex::decode(t[1].as_str().unwrap()).unwrap()).unwrap();
        let flags = parse_flags(t[2].as_str().unwrap());
        let mut valid = check_transaction(&tx);
        for (i, input) in tx.vin.iter().enumerate() {
            if !valid {
                break;
            }
            let spk = &prevouts[&(input.prevout.txid, input.prevout.vout)];
            let checker = TransactionSignatureChecker::new(&tx, i, Amount::ZERO);
            valid = verify_script_with_amount(&input.script_sig, spk, 0, flags, &checker).is_ok();
        }
        count += 1;
        if valid != expect_valid {
            failures.push(serde_json::to_string(t).unwrap());
        }
    }
    assert!(count > 10);
    assert!(
        failures.is_empty(),
        "{} of {} {} vectors disagree with Divi Core:\n{}",
        failures.len(),
        count,
        name,
        failures.join("\n")
    );
}

#[test]
fn divi_core_tx_valid() {
    tx_vectors("tx_valid.json", true);
}

#[test]
fn divi_core_tx_invalid() {
    tx_vectors("tx_invalid.json", false);
}
