// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! Free memory as B2.8 defines it: the smaller of `MemAvailable` and the
//! room left in the node's cgroup, taken as the minimum over the cgroup and
//! every readable ancestor. On macOS: `vm_stat` free + inactive pages.

use std::path::{Path, PathBuf};

/// `PAGE_COUNTER_MAX` on a 64-bit kernel: a v1 limit at (or within a page
/// of) this value means "no limit"
pub const PAGE_COUNTER_MAX: u64 = 9_223_372_036_854_771_712;

/// A cgroup limit file's value; `None` means no limit at this level
/// (`max`, or a v1 value within a page of `PAGE_COUNTER_MAX`) or unparsable
pub fn parse_limit(s: &str) -> Option<u64> {
    let s = s.trim();
    if s == "max" {
        return None;
    }
    let v: u64 = s.parse().ok()?;
    if v >= PAGE_COUNTER_MAX - 4096 {
        return None;
    }
    Some(v)
}

/// What was found, with one line per source for the report
#[derive(Debug, Default)]
pub struct Free {
    pub bytes: Option<u64>,
    pub notes: Vec<String>,
}

/// The room left in a cgroup hierarchy: walk from `dir` up to `root`
/// (inclusive) and take the smallest `limit - usage` of every level that
/// has a limit. `v2` picks the file names.
pub fn cgroup_room(root: &Path, dir: &Path, v2: bool, notes: &mut Vec<String>) -> Option<u64> {
    let (lim, cur) = if v2 {
        ("memory.max", "memory.current")
    } else {
        ("memory.limit_in_bytes", "memory.usage_in_bytes")
    };
    let mut best: Option<u64> = None;
    let mut d: PathBuf = dir.to_path_buf();
    loop {
        if let Ok(l) = std::fs::read_to_string(d.join(lim)) {
            match parse_limit(l.trim()) {
                Some(limit) => {
                    let used = std::fs::read_to_string(d.join(cur))
                        .ok()
                        .and_then(|u| u.trim().parse::<u64>().ok());
                    match used {
                        Some(u) => {
                            let room = limit.saturating_sub(u);
                            let lvl = d.strip_prefix(root).map(|p| p.display().to_string()).unwrap_or_default();
                            notes.push(format!(
                                "cgroup {} level /{}: limit {} MB, used {} MB, room {} MB",
                                if v2 { "v2" } else { "v1" },
                                lvl,
                                limit >> 20,
                                u >> 20,
                                room >> 20
                            ));
                            best = Some(best.map_or(room, |b| b.min(room)));
                        }
                        None => notes.push(format!("cgroup level has a limit but {cur} is unreadable")),
                    }
                }
                None => {}
            }
        }
        if d == root || !d.starts_with(root) {
            break;
        }
        match d.parent() {
            Some(p) => d = p.to_path_buf(),
            None => break,
        }
    }
    best
}

fn meminfo_available() -> Option<u64> {
    let s = std::fs::read_to_string("/proc/meminfo").ok()?;
    s.lines()
        .find(|l| l.starts_with("MemAvailable:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse::<u64>().ok())
        .map(|kb| kb * 1024)
}

/// `vm_stat` free + inactive pages
pub fn parse_vm_stat(s: &str) -> Option<u64> {
    let page: u64 = s
        .lines()
        .next()
        .and_then(|l| l.split("page size of ").nth(1))
        .and_then(|r| r.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(4096);
    let field = |name: &str| -> Option<u64> {
        s.lines()
            .find(|l| l.starts_with(name))
            .and_then(|l| l.split(':').nth(1))
            .and_then(|v| v.trim().trim_end_matches('.').parse::<u64>().ok())
    };
    Some((field("Pages free")? + field("Pages inactive").unwrap_or(0)) * page)
}

/// Free memory for the process `pid` (the node), or for diag itself
pub fn free_memory(pid: Option<u32>) -> Free {
    let mut f = Free::default();
    if cfg!(target_os = "macos") {
        let r = crate::util::run_cmd("vm_stat", &[], std::time::Duration::from_secs(5), 64 << 10);
        f.bytes = parse_vm_stat(&r.text());
        f.notes.push(match f.bytes {
            Some(b) => format!("vm_stat free + inactive: {} MB", b >> 20),
            None => "vm_stat gave no answer".into(),
        });
        return f;
    }
    let avail = meminfo_available();
    f.notes.push(match avail {
        Some(b) => format!("MemAvailable: {} MB", b >> 20),
        None => "MemAvailable unreadable".into(),
    });
    let mut best = avail;
    let who = pid.map(|p| p.to_string()).unwrap_or_else(|| "self".into());
    let cg = std::fs::read_to_string(format!("/proc/{who}/cgroup")).unwrap_or_default();
    for l in cg.lines() {
        let mut parts = l.splitn(3, ':');
        let (_, ctrl, rel) = match (parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c)) => (a, b, c),
            _ => continue,
        };
        let rel = rel.trim_start_matches('/');
        let room = if ctrl.is_empty() {
            let root = Path::new("/sys/fs/cgroup");
            cgroup_room(root, &root.join(rel), true, &mut f.notes)
        } else if ctrl.split(',').any(|c| c == "memory") {
            let root = Path::new("/sys/fs/cgroup/memory");
            cgroup_room(root, &root.join(rel), false, &mut f.notes)
        } else {
            continue;
        };
        if let Some(r) = room {
            best = Some(best.map_or(r, |b| b.min(r)));
        }
    }
    f.bytes = best;
    f
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits() {
        assert_eq!(parse_limit("max"), None);
        assert_eq!(parse_limit("9223372036854771712"), None);
        assert_eq!(parse_limit("9223372036854771000"), None);
        assert_eq!(parse_limit("1073741824\n"), Some(1 << 30));
        assert_eq!(parse_limit("junk"), None);
    }

    #[test]
    fn min_over_ancestors() {
        let t = tempfile::tempdir().unwrap();
        let root = t.path();
        let a = root.join("a");
        let b = a.join("b");
        std::fs::create_dir_all(&b).unwrap();
        std::fs::write(root.join("memory.max"), "max\n").unwrap();
        std::fs::write(a.join("memory.max"), "1000000000\n").unwrap();
        std::fs::write(a.join("memory.current"), "900000000\n").unwrap();
        std::fs::write(b.join("memory.max"), "max\n").unwrap();
        let mut n = vec![];
        assert_eq!(cgroup_room(root, &b, true, &mut n), Some(100_000_000));
        // v1 at PAGE_COUNTER_MAX everywhere: no limit
        std::fs::write(b.join("memory.limit_in_bytes"), "9223372036854771712\n").unwrap();
        std::fs::write(b.join("memory.usage_in_bytes"), "5\n").unwrap();
        assert_eq!(cgroup_room(root, &b, false, &mut n), None);
    }

    #[test]
    fn vm_stat() {
        let s = "Mach Virtual Memory Statistics: (page size of 16384 bytes)\nPages free:                               10.\nPages active:                            5.\nPages inactive:                           2.\n";
        assert_eq!(parse_vm_stat(s), Some(12 * 16384));
    }
}
