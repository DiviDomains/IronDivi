// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The two runtime services the engine and its chain backends need, on both targets:
//! native (tokio, `SystemTime`) and wasm32 in a browser (JS timers, `Date.now`), where
//! there is no tokio timer and `SystemTime::now` panics.

use std::time::Duration;

/// Sleep without blocking the executor.
pub async fn sleep(d: Duration) {
    #[cfg(not(target_arch = "wasm32"))]
    tokio::time::sleep(d).await;
    #[cfg(target_arch = "wasm32")]
    gloo_timers::future::sleep(d).await;
}

/// Wall-clock seconds since the Unix epoch.
pub fn unix_now() -> u64 {
    #[cfg(not(target_arch = "wasm32"))]
    return std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    #[cfg(target_arch = "wasm32")]
    return (js_sys::Date::now() / 1000.0) as u64;
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn sleep_and_clock() {
        let before = super::unix_now();
        super::sleep(std::time::Duration::from_millis(5)).await;
        assert!(before > 1_700_000_000 && super::unix_now() >= before);
    }
}
