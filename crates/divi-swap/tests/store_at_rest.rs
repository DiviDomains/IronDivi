// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
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
