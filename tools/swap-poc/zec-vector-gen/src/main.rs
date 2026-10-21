//! Throwaway cross-check generator (out-of-tree; own `[workspace]` root and `Cargo.lock`).
//!
//! Builds a v5 and a v6 transaction with ONE transparent P2SH input whose redeem script is
//! HTLC-shaped (so scriptPubKey != redeem script), and prints the ZIP-244 transparent sighash
//! computed by librustzcash (`zcash_primitives::transaction::sighash::signature_hash`) as JSON in
//! the field layout of `crates/swap-chain-zec/src/zip244_vectors.rs`.
//! 32-byte values are printed in "zcash display order" (reversed), like the official vectors.
use blake2b_simd::Hash as Blake2bHash;
use sha2::Digest as _;
use transparent::{
    address::Script,
    bundle::{Bundle, OutPoint, TxIn, TxOut},
    sighash::{SignableInput as TSignable, SighashType, TransparentAuthorizingContext},
};
use zcash_primitives::transaction::{
    sighash::{signature_hash, SignableInput},
    txid::TxIdDigester,
    Authorization, Transaction, TransactionData, TxVersion,
};
use zcash_protocol::{consensus::BranchId, value::Zatoshis};
use zcash_script::script;

use zcash_transparent as transparent;

#[derive(Debug)]
struct Auth {
    amounts: Vec<Zatoshis>,
    spks: Vec<Script>,
}
impl transparent::bundle::Authorization for Auth {
    type ScriptSig = Script;
}
impl TransparentAuthorizingContext for Auth {
    fn input_amounts(&self) -> Vec<Zatoshis> {
        self.amounts.clone()
    }
    fn input_scriptpubkeys(&self) -> Vec<Script> {
        self.spks.clone()
    }
}
struct Unauth;
impl Authorization for Unauth {
    type TransparentAuth = Auth;
    type SaplingAuth = sapling_crypto::bundle::Authorized;
    type OrchardAuth = orchard::bundle::Authorized;
}

fn push(s: &mut Vec<u8>, d: &[u8]) {
    assert!(d.len() < 76);
    s.push(d.len() as u8);
    s.extend_from_slice(d);
}

/// Same shape as `divi_swap::htlc::HtlcParams::redeem_script` (114 bytes).
fn redeem_script() -> Vec<u8> {
    let hash: [u8; 32] = sha2::Sha256::digest([0x42u8; 32]).into();
    let claim_pk = [&[0x02u8][..], &[0x11u8; 32][..]].concat();
    let refund_pk = [&[0x03u8][..], &[0x22u8; 32][..]].concat();
    let mut s = vec![0x63, 0xa8]; // OP_IF OP_SHA256
    push(&mut s, &hash);
    s.push(0x88); // OP_EQUALVERIFY
    push(&mut s, &claim_pk);
    s.push(0x67); // OP_ELSE
    push(&mut s, &[0x40, 0x0d, 0x03]); // locktime 200000 (LE script num)
    s.extend([0xb1, 0x75]); // CLTV DROP
    push(&mut s, &refund_pk);
    s.extend([0x68, 0xac]); // OP_ENDIF OP_CHECKSIG
    s
}

fn hash160(b: &[u8]) -> [u8; 20] {
    ripemd::Ripemd160::digest(sha2::Sha256::digest(b)).into()
}

fn rev_hex(h: &[u8]) -> String {
    let mut v = h.to_vec();
    v.reverse();
    hex::encode(v)
}

fn one(version: TxVersion) -> String {
    let redeem = redeem_script();
    let mut spk = vec![0xa9, 0x14];
    spk.extend(hash160(&redeem));
    spk.push(0x87);
    assert_ne!(redeem, spk);
    let amount = 20_000i64;
    let spk_script = Script(script::Code(spk.clone()));
    let p2pkh_out = {
        let mut o = vec![0x76, 0xa9, 0x14];
        o.extend([0x77u8; 20]);
        o.extend([0x88, 0xac]);
        o
    };
    let vin = vec![TxIn::from_parts(
        OutPoint::new([0x5a; 32], 1),
        Script(script::Code(vec![])),
        0xffff_fffe,
    )];
    let vout = vec![TxOut::new(
        Zatoshis::const_from_u64(9_000),
        Script(script::Code(p2pkh_out)),
    )];
    let bundle = Bundle {
        vin,
        vout,
        authorization: Auth {
            amounts: vec![Zatoshis::const_from_u64(amount as u64)],
            spks: vec![spk_script.clone()],
        },
    };
    let branch = match version {
        TxVersion::V5 => BranchId::Nu5,
        _ => BranchId::Nu6_3,
    };
    let data: TransactionData<Unauth> = match version {
        TxVersion::V5 => TransactionData::from_parts(
            version, branch, 0, 3_000_000u32.into(), Some(bundle), None, None, None,
        ),
        _ => TransactionData::from_parts_v6(
            branch, 0, 3_000_000u32.into(), Some(bundle), None, None, None,
        ),
    };
    let parts = data.digest(TxIdDigester);

    // serialise through an Authorized copy
    let auth_bundle = data.transparent_bundle().map(|b| Bundle {
        vin: b
            .vin
            .iter()
            .map(|i| TxIn::from_parts(i.prevout().clone(), i.script_sig().clone(), i.sequence()))
            .collect(),
        vout: b.vout.clone(),
        authorization: transparent::bundle::Authorized,
    });
    let adata = match version {
        TxVersion::V5 => TransactionData::from_parts(
            version, branch, 0, 3_000_000u32.into(), auth_bundle, None, None, None,
        ),
        _ => TransactionData::from_parts_v6(
            branch, 0, 3_000_000u32.into(), auth_bundle, None, None, None,
        ),
    };
    let tx = adata.freeze().unwrap();
    let mut raw = vec![];
    tx.write(&mut raw).unwrap();
    // parse back to confirm
    let _ = Transaction::read(&raw[..], branch).unwrap();

    let b = data.transparent_bundle().unwrap();
    let sh = |ht: SighashType, script_code: &Script| {
        let si = SignableInput::Transparent(TSignable::from_parts(b,
            ht, 0, script_code, &spk_script, Zatoshis::const_from_u64(amount as u64),
        ).unwrap());
        rev_hex(signature_hash(&data, &si, &parts).as_ref())
    };
    let _ = Blake2bHash::as_bytes;
    let redeem_script_obj = Script(script::Code(redeem.clone()));
    // ZIP 244 ignores script_code; both must agree (the digest commits to the scriptPubKey).
    let all = sh(SighashType::ALL, &spk_script);
    assert_eq!(all, sh(SighashType::ALL, &redeem_script_obj));
    format!(
        r#"{{
  "version": "{version:?}",
  "consensus_branch_id": "{:#x}",
  "tx": "{}",
  "txid": "{}",
  "amounts": [{amount}],
  "script_pubkeys": ["{}"],
  "redeem_script": "{}",
  "transparent_input": 0,
  "sighash_all": "{all}",
  "sighash_none": "{}",
  "sighash_single": "{}",
  "sighash_all_anyone": "{}",
  "sighash_none_anyone": "{}",
  "sighash_single_anyone": "{}"
}}"#,
        u32::from(branch),
        hex::encode(&raw),
        rev_hex(tx.txid().as_ref()),
        hex::encode(&spk),
        hex::encode(&redeem),
        sh(SighashType::NONE, &spk_script),
        sh(SighashType::SINGLE, &spk_script),
        sh(SighashType::ALL_ANYONECANPAY, &spk_script),
        sh(SighashType::NONE_ANYONECANPAY, &spk_script),
        sh(SighashType::SINGLE_ANYONECANPAY, &spk_script),
    )
}

fn main() {
    println!("[\n{},\n{}\n]", one(TxVersion::V5), one(TxVersion::V6));
}
