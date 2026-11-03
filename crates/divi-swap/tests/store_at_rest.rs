// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Secrets at rest: an existing swap database is tightened to 0600 on a read-write open,
//! a read-only open leaves the mode alone, record `Debug` output carries no secret, and the
//! stored JSON is byte-identical to what earlier builds wrote.

use divi_swap::api::{Direction, Quote};
use divi_swap::htlc::HtlcParams;
use divi_swap::state::SwapState;
use divi_swap::store::{MakerRecord, Store, TakerRecord};
use divi_swap::taker::TakerState;
use divi_swap::{Amount, Chain};

const PREIMAGE: [u8; 32] = [0xAB; 32];

fn quote() -> Quote {
    Quote {
        id: "q".into(),
        offer_id: "o".into(),
        direction: Direction::TakerPaysBtc,
        counter_chain: Chain::Btc,
        btc_amount: Amount(1),
        divi_amount: Amount(2),
        expires_at: 3,
        maker_btc_pubkey: [2; 33],
        maker_divi_pubkey: [3; 33],
        taker_timeout_secs: 4,
        maker_timeout_secs: 5,
        btc_confirmations: 1,
        divi_confirmations: 1,
    }
}

fn htlc() -> HtlcParams {
    HtlcParams {
        hash: [1; 32],
        claim_pubkey: [2; 33],
        refund_pubkey: [3; 33],
        locktime: 1_800_000_000,
        script_version: Default::default(),
    }
}

fn maker() -> MakerRecord {
    MakerRecord {
        id: "m1".into(),
        created_at: 10,
        state: SwapState::Accepted,
        quote: quote(),
        hash: [1; 32],
        taker_maker_leg_pubkey: [2; 33],
        taker_leg_htlc: htlc(),
        taker_leg_outpoint: None,
        taker_leg_locked: None,
        maker_leg_htlc: None,
        maker_leg_funding: None,
        maker_leg_scan_from: 0,
        maker_mtp_at_lock: None,
        maker_leg_refund: None,
        preimage: Some(PREIMAGE),
        taker_leg_claim: None,
        last_error: None,
        maker_lock_dropped: false,
        maker_lock_sent: false,
        claim_fees: Default::default(),
    }
}

fn taker() -> TakerRecord {
    TakerRecord {
        id: "t1".into(),
        state: TakerState::Prepared,
        quote: quote(),
        preimage: PREIMAGE,
        hash: [1; 32],
        maker_swap_id: None,
        taker_leg_htlc: Some(htlc()),
        taker_leg_funding: None,
        maker_leg_htlc: None,
        maker_leg_outpoint: None,
        maker_leg_amount: None,
        maker_leg_claim: None,
        taker_leg_refund: None,
        claim_declined: None,
        claim_base_feerate: None,
        claim_feerate: None,
        claim_replaced: Vec::new(),
        claim_children: Vec::new(),
        claim_child_replaced: None,
        claim_underpriced: 0,
        last_error: None,
    }
}

/// True when `text` shows the preimage in hex or as a byte array/list.
fn leaks_preimage(text: &str) -> bool {
    text.contains(&hex::encode(PREIMAGE))
        || text.contains("171, 171, 171")
        || text.contains("0xab, 0xab")
        || text.contains("0xAB, 0xAB")
}

/// Compare `got` with `tests/fixtures/store-at-rest/<name>`; `STORE_AT_REST_WRITE=1` writes it.
fn check_fixture(name: &str, got: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/store-at-rest")
        .join(name);
    if std::env::var_os("STORE_AT_REST_WRITE").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, got).unwrap();
    }
    let want = std::fs::read_to_string(&path).unwrap();
    assert_eq!(got, want, "{name}: stored JSON changed");
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn set(p: &Path, m: u32) {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
    }

    fn sidecar(db: &Path, suffix: &str) -> std::path::PathBuf {
        let mut n = db.as_os_str().to_owned();
        n.push(suffix);
        n.into()
    }

    #[test]
    fn existing_loose_db_wal_shm_are_tightened_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        Store::open(&db).unwrap().put_taker_swap(&taker()).unwrap();
        // The state an older build left behind: all three files group/world readable.
        for suffix in ["-wal", "-shm"] {
            std::fs::write(sidecar(&db, suffix), b"").unwrap();
        }
        for suffix in ["", "-wal", "-shm"] {
            set(&sidecar(&db, suffix), 0o644);
        }
        let store = Store::open(&db).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            assert_eq!(mode(&sidecar(&db, suffix)), 0o600, "{suffix:?}");
        }
        // The data is intact and the store works.
        assert_eq!(store.get_taker_swap("t1").unwrap(), Some(taker()));
    }

    #[test]
    fn wal_created_loose_after_a_loose_db_is_still_private() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        drop(Store::open(&db).unwrap());
        set(&db, 0o666);
        let store = Store::open(&db).unwrap();
        store.put_taker_swap(&taker()).unwrap();
        for suffix in ["", "-wal", "-shm"] {
            let p = sidecar(&db, suffix);
            if p.exists() {
                assert_eq!(mode(&p), 0o600, "{suffix:?}");
            }
        }
    }

    #[test]
    fn read_only_open_leaves_the_mode_alone() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("swaps.db");
        drop(Store::open(&db).unwrap());
        set(&db, 0o644);
        let ro = Store::open_read_only(&db).unwrap();
        assert!(ro.get_taker_swap("none").unwrap().is_none());
        assert_eq!(mode(&db), 0o644);
    }

    #[test]
    fn a_file_that_cannot_be_tightened_is_an_error() {
        // /etc/hosts is world-readable and owned by someone else. Skip when this process
        // owns it (running as that owner would let the chmod, and the test, succeed).
        use std::os::unix::fs::MetadataExt;
        let hosts = Path::new("/etc/hosts");
        let Ok(meta) = std::fs::metadata(hosts) else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let mine = std::fs::metadata(dir.path()).unwrap().uid();
        if meta.uid() == mine || meta.permissions().mode() & 0o077 == 0 {
            return;
        }
        let err = Store::open(hosts).err().expect("must refuse").to_string();
        assert!(err.contains("cannot be tightened"), "{err}");
        assert_eq!(
            std::fs::metadata(hosts).unwrap().permissions().mode() & 0o777,
            meta.permissions().mode() & 0o777
        );
    }
}

#[test]
fn record_debug_output_carries_no_secret() {
    let m = format!("{:?}", maker());
    let t = format!("{:?}", taker());
    for (name, text) in [("MakerRecord", &m), ("TakerRecord", &t)] {
        assert!(
            !leaks_preimage(text),
            "{name} Debug leaked the preimage: {text}"
        );
        assert!(text.contains("<redacted>"), "{name}: {text}");
        // The non-secret fields still print their real values.
        assert!(text.contains("locktime: 1800000000"), "{name}: {text}");
    }
    assert!(m.contains("id: \"m1\"") && t.contains("id: \"t1\""));
    // Pretty form (`{:#?}`) and a record nested in an Option/Vec go through the same impl.
    assert!(!leaks_preimage(&format!("{:#?}", taker())));
    assert!(!leaks_preimage(&format!("{:?}", Some(vec![maker()]))));
    // A maker that has not learned the preimage prints None, not <redacted>.
    let mut none = maker();
    none.preimage = None;
    assert!(format!("{none:?}").contains("preimage: None"));
}

#[test]
fn stored_json_is_byte_identical_to_the_fixture() {
    let m = serde_json::to_string(&maker()).unwrap();
    let t = serde_json::to_string(&taker()).unwrap();
    check_fixture("maker-record.json", &m);
    check_fixture("taker-record.json", &t);
    // And the bytes SQLite holds are exactly that.
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("swaps.db");
    let store = Store::open(&db).unwrap();
    store.put_maker_swap(&maker()).unwrap();
    store.put_taker_swap(&taker()).unwrap();
    drop(store);
    let conn = rusqlite::Connection::open(&db).unwrap();
    let mj: String = conn
        .query_row("SELECT json FROM maker_swaps WHERE id='m1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    let tj: String = conn
        .query_row("SELECT json FROM taker_swaps WHERE id='t1'", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(mj, m);
    assert_eq!(tj, t);
}

/// Maker records written before `SwapState::Lost` existed (the at-rest fixture, the v0.2.5
/// daemon's records, the forward-done fixtures) still read, and the at-rest one writes back
/// byte for byte: the new variant moved no existing encoding.
#[test]
fn maker_records_from_before_lost_still_read() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for name in [
        "store-at-rest/maker-record.json",
        "v0.2.5/maker-forward-done.json",
        "v0.2.5/maker-reverse-done.json",
        "maker-forward-done-happy.json",
        "maker-forward-done-casec.json",
    ] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        let rec: MakerRecord =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_ne!(rec.state, SwapState::Lost, "{name}");
    }
    let text = std::fs::read_to_string(dir.join("store-at-rest/maker-record.json")).unwrap();
    let rec: MakerRecord = serde_json::from_str(&text).unwrap();
    assert_eq!(serde_json::to_string(&rec).unwrap(), text);
}

/// Maker records written before `maker_lock_sent` existed read it as false (unsent, as
/// before), the at-rest one writes back byte for byte, and a sent lock round-trips through
/// the store under that key, which is left out while false.
#[test]
fn maker_records_from_before_maker_lock_sent_read_unsent() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for name in [
        "store-at-rest/maker-record.json",
        "v0.2.5/maker-forward-done.json",
        "v0.2.5/maker-reverse-done.json",
        "maker-forward-done-happy.json",
        "maker-forward-done-casec.json",
    ] {
        let text = std::fs::read_to_string(dir.join(name)).unwrap();
        assert!(!text.contains("maker_lock_sent"), "{name}");
        let rec: MakerRecord =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!rec.maker_lock_sent, "{name}");
    }
    let text = std::fs::read_to_string(dir.join("store-at-rest/maker-record.json")).unwrap();
    let rec: MakerRecord = serde_json::from_str(&text).unwrap();
    assert_eq!(serde_json::to_string(&rec).unwrap(), text);

    let mut m = maker();
    m.maker_lock_sent = true;
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"maker_lock_sent\":true"), "{json}");
    let store = Store::in_memory().unwrap();
    store.put_maker_swap(&m).unwrap();
    assert!(store.get_maker_swap("m1").unwrap().unwrap().maker_lock_sent);
}

/// A `Lost` maker record goes through the store: JSON `"state":"Lost"` (the variant name,
/// like every other maker state), the `state` column `lost`, read back and listed as `Lost`.
#[test]
fn a_lost_maker_record_round_trips_through_the_store() {
    let mut m = maker();
    m.state = SwapState::Lost;
    m.last_error = Some("lost: the taker leg was refunded".into());
    let json = serde_json::to_string(&m).unwrap();
    assert!(json.contains("\"state\":\"Lost\""), "{json}");
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("swaps.db");
    let store = Store::open(&db).unwrap();
    store.put_maker_swap(&m).unwrap();
    let back = store.get_maker_swap("m1").unwrap().unwrap();
    assert_eq!(back.state, SwapState::Lost);
    assert!(back.state.is_terminal());
    assert_eq!(back.last_error, m.last_error);
    let listed = store.list_maker_swaps().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].state, SwapState::Lost);
    drop(store);
    let conn = rusqlite::Connection::open(&db).unwrap();
    let (col, stored): (String, String) = conn
        .query_row(
            "SELECT state, json FROM maker_swaps WHERE id='m1'",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(col, "lost");
    assert_eq!(stored, json);
}

/// A pending CPFP child replacement's predecessor (`claim_child_replaced`) goes through the
/// store on both records under that key and is left out while empty, so records from before
/// the field read and write back unchanged.
#[test]
fn a_replaced_cpfp_child_round_trips_and_is_left_out_while_empty() {
    let child = divi_swap::SignedTx {
        txid: divi_swap::Txid([7; 32]),
        raw: vec![1, 2, 3],
    };
    let mut t = taker();
    assert!(!serde_json::to_string(&t)
        .unwrap()
        .contains("claim_child_replaced"));
    t.claim_child_replaced = Some((child.clone(), 42));
    let mut m = maker();
    assert!(!serde_json::to_string(&m)
        .unwrap()
        .contains("claim_child_replaced"));
    m.claim_fees.claim_child_replaced = Some((child.clone(), 42));
    assert!(serde_json::to_string(&m)
        .unwrap()
        .contains("\"claim_child_replaced\":"));
    let store = Store::in_memory().unwrap();
    store.put_taker_swap(&t).unwrap();
    store.put_maker_swap(&m).unwrap();
    let back = store.get_taker_swap("t1").unwrap().unwrap();
    assert_eq!(back.claim_child_replaced, Some((child.clone(), 42)));
    let back = store.get_maker_swap("m1").unwrap().unwrap();
    assert_eq!(back.claim_fees.claim_child_replaced, Some((child, 42)));
}
