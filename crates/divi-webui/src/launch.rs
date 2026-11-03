// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Opening the browser at start, already signed in. The daemon makes a
//! one-time launch token, opens `/launch?t=<token>`, and the first request
//! that presents it gets a session cookie; the token is then dead. It lives
//! in memory only, for a minute, and never reaches the log. The browser
//! command sees it in its arguments for that minute: the same user's
//! processes can read it there, and they can read the data directory too.

use std::process::Stdio;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::process::Command;

use crate::auth::{constant_time_eq, random_hex};

/// How long the browser has to present the token
pub const LAUNCH_TTL: Duration = Duration::from_secs(60);

/// The one launch token, if it is still unused
#[derive(Default)]
pub struct LaunchToken {
    slot: Mutex<Option<(String, Instant)>>,
}

impl LaunchToken {
    /// A fresh token, replacing any earlier one
    pub fn issue(&self) -> String {
        let token = random_hex(32);
        *self.slot.lock() = Some((token.clone(), Instant::now()));
        token
    }

    /// True once for the live token; any try, right or wrong, after expiry
    /// clears it
    pub fn redeem(&self, presented: &str) -> bool {
        let mut slot = self.slot.lock();
        let Some((token, issued)) = slot.as_ref() else {
            return false;
        };
        if issued.elapsed() >= LAUNCH_TTL {
            *slot = None;
            return false;
        }
        if constant_time_eq(presented.as_bytes(), token.as_bytes()) {
            *slot = None;
            return true;
        }
        false
    }
}

/// Is someone at this machine's screen? False over SSH, without a display
/// on Linux and the BSDs, and for a background daemon.
pub fn desktop_session() -> bool {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    if set("SSH_CONNECTION") || set("SSH_TTY") || set("SSH_CLIENT") {
        return false;
    }
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        return true;
    }
    set("DISPLAY") || set("WAYLAND_DISPLAY")
}

/// Open `url` in the default browser, detached; false if no opener ran
pub fn open_browser(url: &str) -> bool {
    let mut cmd = if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else if cfg!(target_os = "windows") {
        // `start` treats its first quoted argument as a title
        let mut c = Command::new("cmd");
        c.args(["/C", "start", ""]).arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Tokio's child reaper reaps the opener once it exits; kill_on_drop stays false
    cmd.spawn().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_works_once() {
        let l = LaunchToken::default();
        let t = l.issue();
        assert!(!l.redeem("nope"));
        assert!(l.redeem(&t));
        assert!(!l.redeem(&t));
    }

    #[test]
    fn new_token_kills_old() {
        let l = LaunchToken::default();
        let a = l.issue();
        let b = l.issue();
        assert!(!l.redeem(&a));
        assert!(l.redeem(&b));
    }
}
