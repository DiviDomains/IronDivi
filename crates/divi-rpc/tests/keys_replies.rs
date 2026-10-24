// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Key import/export and wallet-upkeep RPC replies as Divi Core 3.0.0's divid
//! gives them (rpcdump.cpp, rpcwallet.cpp), checked against divid with
//! scripts/keys-replies/run.sh.

use divi_primitives::ChainMode;
use divi_rpc::{Params, Request, RequestId, Response, RpcError, RpcServer};
use divi_storage::{Chain, ChainDatabase, ChainParams, NetworkType};
use divi_wallet::{HdWallet, Network, WalletDb};
use serde_json::{json, Value};
use std::sync::Arc;

struct Node {
    server: RpcServer,
    wallet: Arc<WalletDb>,
    _dir: tempfile::TempDir,
}

fn node() -> Node {
    let dir = tempfile::tempdir().unwrap();
    let db = Arc::new(ChainDatabase::open(dir.path().join("chain")).unwrap());
    let chain = Arc::new(
        Chain::new(
            db,
            ChainParams::for_network(NetworkType::Regtest, ChainMode::Divi),
        )
        .unwrap(),
    );
    let wallet = Arc::new(
        WalletDb::create_persistent(
            &dir.path().join("wallet"),
            Network::Regtest,
            HdWallet::new(ChainMode::Divi).unwrap(),
        )
        .unwrap(),
    );
    Node {
        server: RpcServer::with_wallet(chain, wallet.clone()),
        wallet,
        _dir: dir,
    }
}

impl Node {
    fn call(&self, method: &str, params: Vec<Value>) -> Response {
        self.server.handle_request(Request {
            jsonrpc: "1.0".to_string(),
            id: RequestId::Number(1),
            method: method.to_string(),
            params: Params::Array(params),
        })
    }

    fn err(&self, method: &str, params: Vec<Value>) -> RpcError {
        let reply = self.call(method, params.clone());
        reply
            .error
            .unwrap_or_else(|| panic!("{method} {params:?} answered {:?}", reply.result))
    }

    fn ok(&self, method: &str, params: Vec<Value>) -> Value {
        let reply = self.call(method, params.clone());
        assert!(
            reply.error.is_none(),
            "{method} {params:?}: {:?}",
            reply.error
        );
        reply.result.expect("result")
    }
}

/// A wrong number of arguments is answered with the call's help as a -1 error,
/// before the wallet or any argument is looked at (rpcdump.cpp:43, :107, :172,
/// :251, :297; rpcwallet.cpp:2527, :2546)
#[test]
fn wrong_argument_counts_answer_with_the_help() {
    let n = node();
    let addr = n.wallet.new_receiving_address().unwrap().to_string();
    for (method, params) in [
        ("importprivkey", vec![]),
        (
            "importprivkey",
            vec![json!("k"), json!("l"), json!(true), json!(1)],
        ),
        ("importaddress", vec![]),
        (
            "importaddress",
            vec![json!(addr), json!("l"), json!(true), json!(1)],
        ),
        ("dumpprivkey", vec![]),
        ("dumpprivkey", vec![json!(addr), json!(1)]),
        ("backupwallet", vec![]),
        ("keypoolrefill", vec![json!(5), json!(5)]),
        ("bip38paperwallet", vec![]),
        ("bip38decrypt", vec![json!("k")]),
    ] {
        let e = n.err(method, params.clone());
        assert_eq!(e.code, -1, "{method} {params:?}: {}", e.message);
        assert!(
            e.message.starts_with(method) && e.message.contains('\n'),
            "{method} {params:?}: {}",
            e.message
        );
    }
}

fn code_and_text(e: RpcError) -> (i32, String) {
    (e.code, e.message)
}

/// Arguments are read as json_spirit reads them (get_str, get_bool, get_int),
/// in Divi Core's order (rpcdump.cpp:59-70, :111-129, :184-186;
/// rpcwallet.cpp:2531, :2552-2556)
#[test]
fn arguments_are_read_as_divid_reads_them() {
    let n = node();
    let addr = n.wallet.new_receiving_address().unwrap().to_string();
    let typed = |t: &str, wanted: &str| (-1, format!("value is type {t}, expected {wanted}"));
    for (method, params, expected) in [
        ("importprivkey", vec![json!(1)], typed("int", "str")),
        (
            "importprivkey",
            vec![json!("k"), json!(7)],
            typed("int", "str"),
        ),
        (
            "importprivkey",
            vec![json!("k"), json!("x"), json!("yes")],
            typed("str", "bool"),
        ),
        ("importaddress", vec![json!(1)], typed("int", "str")),
        (
            "importaddress",
            vec![json!(addr), json!("watch"), json!("no")],
            typed("str", "bool"),
        ),
        ("dumpprivkey", vec![json!(1)], typed("int", "str")),
        ("backupwallet", vec![json!(1)], typed("int", "str")),
        ("keypoolrefill", vec![json!("5")], typed("str", "int")),
        ("keypoolrefill", vec![json!(1.5)], typed("real", "int")),
        (
            "keypoolrefill",
            vec![json!(-1)],
            (-8, "Invalid parameter, expected valid size.".to_string()),
        ),
        (
            "importaddress",
            vec![json!(addr)],
            (
                -4,
                "The wallet already contains the private key for this address or script"
                    .to_string(),
            ),
        ),
    ] {
        assert_eq!(
            code_and_text(n.err(method, params.clone())),
            expected,
            "{method} {params:?}"
        );
    }
    // 0 is the default size (rpcwallet.cpp:2551-2556)
    assert_eq!(n.ok("keypoolrefill", vec![json!(0)]), Value::Null);
    assert_eq!(n.ok("keypoolrefill", vec![]), Value::Null);
}

/// On a locked wallet the calls that unlock first answer -13 whatever their
/// arguments; keypoolrefill checks its size before (rpcdump.cpp:59, :184;
/// rpcwallet.cpp:2552-2559)
#[test]
fn locked_wallet_is_checked_where_divid_checks_it() {
    let n = node();
    n.wallet.encrypt_wallet("pass").unwrap();
    let locked = (
        -13,
        "Error: Please enter the wallet passphrase with walletpassphrase first.".to_string(),
    );
    for (method, params) in [
        ("dumpprivkey", vec![json!("notanaddress")]),
        ("dumpprivkey", vec![json!(1)]),
        ("importprivkey", vec![json!(1)]),
        ("importprivkey", vec![json!("notakey")]),
        ("keypoolrefill", vec![json!(5)]),
    ] {
        assert_eq!(
            code_and_text(n.err(method, params.clone())),
            locked,
            "{method} {params:?}"
        );
    }
    assert_eq!(
        code_and_text(n.err("keypoolrefill", vec![json!(-1)])),
        (-8, "Invalid parameter, expected valid size.".to_string())
    );
}

/// encryptwallet answers as Divi Core 3.0.0 does, and leaves the wallet locked
/// (rpcwallet.cpp:2729-2733)
#[test]
fn encryptwallet_answers_as_divid() {
    let n = node();
    assert_eq!(
        n.ok("encryptwallet", vec![json!("pass")]),
        json!("Wallet reloaded!")
    );
    assert!(n.wallet.is_locked());
}

/// The P2PKH version of a regtest address, which BIP38's address hash uses
const REGTEST_P2PKH: u8 = 139;

/// bip38decrypt as Divi Core (rpcdump.cpp:295-347): it adds the key to the
/// wallet and answers its address in the node's network; a key already held,
/// one that does not decrypt and a locked wallet are refused as Core refuses
/// them. A key Core's bip38paperwallet made (address hash = the first bytes of
/// SHA256d of the regtest address) decrypts.
#[test]
fn bip38decrypt_adds_the_key_as_divid() {
    let n = node();
    let secret = divi_crypto::keys::SecretKey::new_random();
    let mut key = [0u8; 32];
    key.copy_from_slice(secret.as_bytes());
    let encrypted = divi_crypto::bip38_encrypt(&key, "pw", true, REGTEST_P2PKH).unwrap();
    let address = divi_wallet::Address::p2pkh(&secret.public_key(), Network::Regtest);

    // Compared without printing the reply, which could hold a key
    let r = n.ok("bip38decrypt", vec![json!(encrypted), json!("pw")]);
    assert!(
        r == json!({"Address": address.to_string()}),
        "bip38decrypt did not answer the key's address"
    );
    assert!(n.wallet.is_mine(&address) && !n.wallet.is_watch_only(&address));

    let wallet_error = |text: &str| (-4, text.to_string());
    assert_eq!(
        code_and_text(n.err("bip38decrypt", vec![json!(encrypted), json!("pw")])),
        wallet_error("Key already held by wallet")
    );
    assert_eq!(
        code_and_text(n.err("bip38decrypt", vec![json!("notakey"), json!("pw")])),
        wallet_error("Failed To Decrypt")
    );
    assert_eq!(
        code_and_text(n.err("bip38decrypt", vec![json!(encrypted), json!("other")])),
        wallet_error("Failed To Decrypt")
    );
    assert_eq!(
        code_and_text(n.err("bip38decrypt", vec![json!(1), json!("pw")])),
        (-1, "value is type int, expected str".to_string())
    );

    // bip38paperwallet's key decrypts in the same network
    let paper = n.ok("bip38paperwallet", vec![json!("pw2")]);
    let r = n.ok(
        "bip38decrypt",
        vec![paper["Encrypted Key"].clone(), json!("pw2")],
    );
    assert_eq!(r["Address"], paper["Address"]);

    n.wallet.encrypt_wallet("pass").unwrap();
    let locked = (
        -13,
        "Error: Please enter the wallet passphrase with walletpassphrase first.".to_string(),
    );
    assert_eq!(
        code_and_text(n.err("bip38decrypt", vec![json!("notakey"), json!("pw")])),
        locked
    );
    assert_eq!(
        code_and_text(n.err("bip38paperwallet", vec![json!(1)])),
        locked
    );
}
