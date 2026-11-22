use divi_swap::Store;
use std::{fs, process::Command};

#[test]
fn incomplete_live_configuration_fails_before_opening_store() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("maker.toml");
    let db = dir.path().join("swaps.db");
    // A regression into daemon startup must also exit during this process test.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    for existing in [false, true] {
        if existing {
            drop(Store::open(&db).unwrap());
        }
        let before = fs::read(&db).ok();
        for sections in ["", "[divi]", "[btc]"] {
            let key = if sections.is_empty() {
                ""
            } else {
                "key = 'credential:unused'"
            };
            fs::write(
                &config,
                format!(
                    "listen = '{address}'\ndb_path = '{}'\n{sections}\n{key}\n",
                    db.display()
                ),
            )
            .unwrap();
            for flags in [&[][..], &["--backend", "live"][..]] {
                let result = Command::new(env!("CARGO_BIN_EXE_divi-swapd"))
                    .arg("--config")
                    .arg(&config)
                    .args(flags)
                    .output()
                    .unwrap();
                let err = String::from_utf8_lossy(&result.stderr);
                assert!(
                    !result.status.success() && err.contains("requires both [divi] and [btc]"),
                    "{err}"
                );
                assert_eq!(fs::read(&db).ok(), before);
            }
        }
    }
}

#[test]
fn backend_flag_conflicts_with_store_commands() {
    for flag in ["--reservations", "--xmr-inflight", "--release-reservation"] {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_divi-swapd"));
        cmd.args(["--config", "unused", "--backend", "mock", flag]);
        if flag == "--release-reservation" {
            cmd.args(["00", "--chain", "btc"]);
        }
        let result = cmd.output().unwrap();
        assert_eq!(result.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&result.stderr).contains("cannot be used with"));
    }
}

#[test]
fn backend_is_durable_and_legacy_stores_require_review() {
    use divi_swap::store::DaemonMode::{Live, Mock};
    let dir = tempfile::tempdir().unwrap();
    for (name, mode, other) in [("live", Live, Mock), ("mock", Mock, Live)] {
        let db = dir.path().join(name);
        drop(Store::open_daemon(&db, mode).unwrap());
        drop(Store::open_daemon(&db, mode).unwrap());
        let before = fs::read(&db).unwrap();
        assert!(Store::open_daemon(&db, other).is_err());
        assert!(Store::open(&db).is_err());
        assert_eq!(fs::read(&db).unwrap(), before);
        Store::open_read_only(&db).unwrap();
    }
    let db = dir.path().join("legacy");
    drop(Store::open(&db).unwrap());
    let before = fs::read(&db).unwrap();
    for mode in [Live, Mock] {
        assert!(Store::open_daemon(&db, mode).is_err());
        assert_eq!(fs::read(&db).unwrap(), before);
    }
}

#[test]
fn racing_backends_cannot_both_acquire_an_empty_database() {
    use divi_swap::store::DaemonMode::{Live, Mock};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("race.db");
    let gate = std::sync::Barrier::new(2);
    let attempt = |mode| {
        gate.wait();
        Store::open_daemon(&db, mode).is_ok()
    };
    let (live, mock) = std::thread::scope(|scope| {
        let live = scope.spawn(|| attempt(Live));
        let mock = attempt(Mock);
        (live.join().unwrap(), mock)
    });
    assert_ne!(live, mock);
    assert!(Store::open_daemon(&db, if live { Live } else { Mock }).is_ok());
}

#[cfg(unix)]
#[test]
fn write_failure_leaves_an_empty_file_retryable() {
    use divi_swap::store::DaemonMode::{Live, Mock};
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("readonly.db");
    fs::write(&db, []).unwrap();
    fs::set_permissions(&db, fs::Permissions::from_mode(0o400)).unwrap();
    // A privileged test runner can write through these permissions.
    if fs::OpenOptions::new().write(true).open(&db).is_ok() {
        return;
    }
    assert!(Store::open_daemon(&db, Mock).is_err());
    assert!(fs::read(&db).unwrap().is_empty());
    fs::set_permissions(&db, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Store::open_daemon(&db, Live).is_ok());
}
