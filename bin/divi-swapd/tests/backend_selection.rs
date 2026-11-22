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
