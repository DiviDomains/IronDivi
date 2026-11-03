// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Reviewer question 5: no shipped entry point builds a taker without the profile floor.
//! Pins today's answer by scanning the non-test source of every binary and library crate:
//! each `Taker::new(` / `XmrTaker::new(` call must chain `.with_profile_floor(` and the set of
//! call sites is exactly the four in `bin/divi-swap/src/main.rs`. A new construction site, or one
//! that drops the floor, fails here and needs this list (and the review answer) updated.

use std::fs;
use std::path::{Path, PathBuf};

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            let n = p.file_name().unwrap().to_string_lossy().into_owned();
            if n != "target" && n != "tests" && n != "examples" && n != "benches" {
                rs_files(&p, out);
            }
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn every_shipped_taker_construction_applies_the_profile_floor() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rs_files(&root.join("bin"), &mut files);
    rs_files(&root.join("crates"), &mut files);
    assert!(files.len() > 50, "scan found only {} files", files.len());

    let mut sites: Vec<(String, usize)> = Vec::new();
    for f in &files {
        let src = fs::read_to_string(f).unwrap();
        // Production code only: everything before the first unit-test module.
        let prod = src.split("#[cfg(test)]").next().unwrap();
        let rel = f
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace("../", "");
        for (i, _) in prod.match_indices("Taker::new(") {
            let line_start = prod[..i].rfind('\n').map_or(0, |n| n + 1);
            if prod[line_start..].trim_start().starts_with("//") {
                continue; // doc comment or comment
            }
            let tail = &prod[i..prod.len().min(i + 400)];
            let stmt = tail.split(';').next().unwrap();
            assert!(
                stmt.contains(".with_profile_floor("),
                "{rel}: a Taker is built without .with_profile_floor(..): {stmt}"
            );
            let line = prod[..i].matches('\n').count() + 1;
            sites.push((rel.clone(), line));
        }
    }
    let by_file: std::collections::BTreeMap<_, usize> =
        sites.iter().fold(Default::default(), |mut m, (f, _)| {
            *m.entry(f.clone()).or_default() += 1;
            m
        });
    let expect: std::collections::BTreeMap<String, usize> =
        [("bin/divi-swap/src/main.rs".to_string(), 4)].into();
    assert_eq!(
        by_file, expect,
        "taker construction sites changed: {sites:?}"
    );
}
