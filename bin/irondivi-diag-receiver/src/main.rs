// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! `irondivi-diag-receiver`: the §9 receiver behind nginx.
//!
//! Configuration, from the environment only:
//! - `DIAG_LISTEN`  address to bind (default `127.0.0.1:8795`; loopback only)
//! - `DIAG_DATA`    data dir (default `$STATE_DIRECTORY`, set by systemd)
//! - `DIAG_TOKEN_SHA256_FILE` file holding the hex SHA-256 of the developer
//!   token (default `$CREDENTIALS_DIRECTORY/token.sha256`); missing turns the
//!   developer routes off
//!
//! It prints one line at start-up and nothing per request.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use irondivi_diag_receiver::{now, router, sweep, AppState, Config, Limiter};

fn token_hash() -> Option<[u8; 32]> {
    let p = std::env::var_os("DIAG_TOKEN_SHA256_FILE")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("CREDENTIALS_DIRECTORY").map(|d| PathBuf::from(d).join("token.sha256")))?;
    let s = std::fs::read_to_string(p).ok()?;
    let v = hex::decode(s.trim()).ok()?;
    v.try_into().ok()
}

fn main() {
    // a panic message could carry request data; print only that it happened
    std::panic::set_hook(Box::new(|_| eprintln!("irondivi-diag-receiver: internal error (details withheld)")));
    #[cfg(unix)]
    unsafe {
        libc_umask(0o077);
    }
    let listen: SocketAddr = std::env::var("DIAG_LISTEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 8795)));
    if !listen.ip().is_loopback() {
        eprintln!("irondivi-diag-receiver: refusing to bind {listen}: loopback only, nginx is the front");
        std::process::exit(2);
    }
    let data = std::env::var_os("DIAG_DATA")
        .or_else(|| std::env::var_os("STATE_DIRECTORY"))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("irondivi-diag-receiver: set DIAG_DATA or run under systemd with StateDirectory=");
            std::process::exit(2);
        });
    if let Err(e) = std::fs::create_dir_all(&data) {
        eprintln!("irondivi-diag-receiver: data dir {}: {e}", data.display());
        std::process::exit(2);
    }
    let token = token_hash();
    let st = Arc::new(AppState { cfg: Config { data: data.clone(), token_sha256: token }, limiter: Limiter::new() });

    let rt = tokio::runtime::Builder::new_multi_thread().enable_all().build().expect("runtime");
    rt.block_on(async move {
        let sweeper = st.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(3600));
            loop {
                tick.tick().await;
                let d = sweeper.cfg.data.clone();
                let n = now();
                let _ = tokio::task::spawn_blocking(move || sweep(&d, n)).await;
                sweeper.limiter.forget_old(n);
            }
        });
        let l = match tokio::net::TcpListener::bind(listen).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("irondivi-diag-receiver: bind {listen}: {e}");
                std::process::exit(2);
            }
        };
        eprintln!(
            "irondivi-diag-receiver {} listening on {listen}, data {}, developer routes {}",
            env!("CARGO_PKG_VERSION"),
            data.display(),
            if token.is_some() { "on" } else { "off (no token hash)" }
        );
        if let Err(e) = axum::serve(l, router(st)).await {
            eprintln!("irondivi-diag-receiver: server stopped: {e}");
            std::process::exit(1);
        }
    });
}

#[cfg(unix)]
extern "C" {
    #[link_name = "umask"]
    fn libc_umask(mask: u32) -> u32;
}
