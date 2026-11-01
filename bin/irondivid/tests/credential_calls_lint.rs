// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The kernel resets the non-dumpable flag (`disable_core_dumps`, D5) on any credential change,
//! after which a pipe `core_pattern` handler would store a core holding wallet keys. This lint
//! fails on a credential call in a workspace crate unless `PR_SET_DUMPABLE` follows it in the
//! same function (diag plan A5 "Non-dumpable process", X2).

use std::fs;
use std::path::{Path, PathBuf};

/// The ten credential calls; their `libc::`, `nix::unistd::` and bare spellings all end in
/// one of these names.
const CREDENTIAL_CALLS: &[&str] = &[
    "setuid",
    "setgid",
    "setresuid",
    "setresgid",
    "setreuid",
    "setregid",
    "setfsuid",
    "setfsgid",
    "capset",
    "setgroups",
];

/// The `caps` crate changes capabilities (and so credentials) through these paths.
const CAPS_CALLS: &[&str] = &["caps::set", "caps::raise", "caps::drop", "caps::clear"];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("bin/irondivid sits two levels below the workspace root")
        .to_path_buf()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if path.is_dir() {
            if name != "target" && name != ".git" && name != "node_modules" {
                rust_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The source with `//` comments blanked, so a name in a comment is not a call. Lines keep
/// their numbers.
fn strip_line_comments(src: &str) -> Vec<String> {
    src.lines()
        .map(|line| match line.find("//") {
            Some(i) => line[..i].to_string(),
            None => line.to_string(),
        })
        .collect()
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Whether `line` calls `name`: the name is not part of a longer identifier (a `::` path
/// before it is fine) and an opening parenthesis follows.
fn calls(line: &str, name: &str) -> bool {
    let bytes = line.as_bytes();
    let mut from = 0;
    while let Some(i) = line[from..].find(name) {
        let start = from + i;
        let end = start + name.len();
        let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
        let rest = line[end..].trim_start();
        // A turbofish or generic call is still a call.
        let after_ok = rest.starts_with('(') || rest.starts_with("::<");
        if before_ok && (end == bytes.len() || !is_ident_byte(bytes[end])) && after_ok {
            return true;
        }
        from = end;
    }
    false
}

fn starts_fn(line: &str) -> bool {
    let t = line.trim_start();
    let t = t.strip_prefix("pub(crate) ").unwrap_or(t);
    let t = t.strip_prefix("pub ").unwrap_or(t);
    let t = t.strip_prefix("const ").unwrap_or(t);
    let t = t.strip_prefix("async ").unwrap_or(t);
    let t = t.strip_prefix("unsafe ").unwrap_or(t);
    let t = t.strip_prefix("extern \"C\" ").unwrap_or(t);
    t.starts_with("fn ")
}

/// Every credential call in `lines` not followed by `PR_SET_DUMPABLE` before the next
/// function starts, as `(line number, name)`.
fn unguarded(lines: &[String]) -> Vec<(usize, &'static str)> {
    let mut found = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let hit = CREDENTIAL_CALLS
            .iter()
            .chain(CAPS_CALLS)
            .find(|name| calls(line, name));
        let Some(name) = hit else {
            continue;
        };
        let guarded = lines[i..]
            .iter()
            .enumerate()
            .take_while(|(j, l)| *j == 0 || !starts_fn(l))
            .any(|(_, l)| l.contains("PR_SET_DUMPABLE"));
        if !guarded {
            found.push((i + 1, *name));
        }
    }
    found
}

#[test]
fn no_credential_call_without_pr_set_dumpable() {
    let root = workspace_root();
    let this_file = Path::new(file!())
        .file_name()
        .expect("test file name")
        .to_owned();
    let mut files = Vec::new();
    for dir in ["bin", "crates", "tools"] {
        rust_files(&root.join(dir), &mut files);
    }
    assert!(
        files.len() > 50,
        "found only {} Rust files under {}; the walk is wrong",
        files.len(),
        root.display()
    );
    let mut failures = Vec::new();
    for path in files {
        if path.file_name() == Some(this_file.as_os_str()) {
            continue;
        }
        let Ok(src) = fs::read_to_string(&path) else {
            continue;
        };
        for (line, name) in unguarded(&strip_line_comments(&src)) {
            failures.push(format!(
                "{}:{line}: {name} without PR_SET_DUMPABLE 0 after it in the same function",
                path.strip_prefix(&root).unwrap_or(&path).display()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "a credential change resets the non-dumpable flag (D5); set it again:\n{}",
        failures.join("\n")
    );
}

#[test]
fn the_lint_catches_what_it_should() {
    let src = |s: &str| strip_line_comments(s);
    // A bare call, a libc call and a caps call, unguarded.
    assert_eq!(
        unguarded(&src(
            "fn a() {\n    unsafe { libc::setresuid(1, 1, 1) };\n}\n"
        ))
        .len(),
        1
    );
    assert_eq!(
        unguarded(&src("fn a() { nix::unistd::setgid(g)?; }\n")).len(),
        1
    );
    assert_eq!(
        unguarded(&src("fn a() { caps::drop(None, set, cap)?; }\n")).len(),
        1
    );
    // Guarded in the same function.
    assert!(unguarded(&src(
        "fn a() {\n    libc::setuid(1);\n    libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);\n}\n"
    ))
    .is_empty());
    // A guard in the next function does not count.
    assert_eq!(
        unguarded(&src(
            "fn a() {\n    libc::setuid(1);\n}\nfn b() {\n    libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);\n}\n"
        ))
        .len(),
        1
    );
    // Not calls: comments, longer identifiers, a getter.
    assert!(unguarded(&src(
        "// setuid(0) here would reset the flag\nfn a() { my_setuid(1); getuid(); let setgid_x = 1; }\n"
    ))
    .is_empty());
}
