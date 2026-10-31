// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Build facts for the A7 start-up record: rustc, git commit, target,
//! profile and whether frame pointers were forced. A fact that cannot be
//! found is `-`; the build never fails over one.

use std::process::Command;

fn main() {
    let out = |cmd: &str, args: &[&str]| -> String {
        Command::new(cmd)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "-".into())
    };
    let rustc = std::env::var("RUSTC").unwrap_or_else(|_| "rustc".into());
    println!("cargo:rustc-env=IRONDIVID_RUSTC={}", out(&rustc, &["--version"]));
    println!(
        "cargo:rustc-env=IRONDIVID_GIT={}",
        out("git", &["rev-parse", "--short=12", "HEAD"])
    );
    let env = |name: &str| std::env::var(name).unwrap_or_else(|_| "-".into());
    println!("cargo:rustc-env=IRONDIVID_TARGET={}", env("TARGET"));
    println!("cargo:rustc-env=IRONDIVID_PROFILE={}", env("PROFILE"));
    let flags = std::env::var("CARGO_ENCODED_RUSTFLAGS").unwrap_or_default();
    let forced = flags.contains("force-frame-pointers=yes")
        || flags.contains("force-frame-pointers=on")
        || flags.contains("force-frame-pointers=true");
    println!(
        "cargo:rustc-env=IRONDIVID_FRAME_POINTERS={}",
        if forced { "forced" } else { "default" }
    );
    // A new commit changes the sha; with no checkout there is nothing to watch
    let head = std::path::Path::new("../../.git/logs/HEAD");
    if head.exists() {
        println!("cargo:rerun-if-changed={}", head.display());
    }
    println!("cargo:rerun-if-changed=build.rs");
}
