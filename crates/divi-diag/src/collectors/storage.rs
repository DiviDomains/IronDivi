// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B2.6 storage (with the R1 b fsync test) and B2.7 data dir inventory.

use super::{cmd_block_t, head, LINUX};
use crate::ctx::{Ctx, DataDir};
use crate::frame::Out;
use crate::outln;
use crate::util;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// One line of /proc/self/mountinfo
#[derive(Debug, Clone)]
pub struct Mount {
    pub point: String,
    pub fstype: String,
    pub source: String,
    pub opts: String,
}

pub fn mounts() -> Vec<Mount> {
    let s = util::read_small(Path::new("/proc/self/mountinfo"), 4 << 20).unwrap_or_default();
    s.lines()
        .filter_map(|l| {
            let (a, b) = l.split_once(" - ")?;
            let a: Vec<&str> = a.split(' ').collect();
            let b: Vec<&str> = b.split(' ').collect();
            Some(Mount {
                point: unescape(a.get(4)?),
                opts: format!("{},{}", a.get(5)?, b.get(2).unwrap_or(&"")),
                fstype: b.first()?.to_string(),
                source: b.get(1).unwrap_or(&"").to_string(),
            })
        })
        .collect()
}

fn unescape(s: &str) -> String {
    s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")
}

/// The mount a path is on: the longest mount point that prefixes it
pub fn mount_of<'a>(ms: &'a [Mount], p: &Path) -> Option<&'a Mount> {
    let p = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
    ms.iter()
        .filter(|m| p.starts_with(&m.point))
        .max_by_key(|m| m.point.len())
}

fn source_shown(src: &str, fstype: &str) -> String {
    let net = ["nfs", "nfs4", "cifs", "smb3", "smbfs", "sshfs", "fuse.sshfs", "9p", "glusterfs", "fuse.glusterfs", "ceph"];
    if net.contains(&fstype) || src.contains(':') || src.starts_with("//") {
        "<network source>".into()
    } else {
        src.to_string()
    }
}

fn space_line(o: &mut Out, what: &str, p: &Path) {
    match util::statvfs(p) {
        Some((total, free, files, ffree)) => outln!(
            o,
            "{what}: {} free of {} ({}%), inodes {} free of {}",
            util::human(free),
            util::human(total),
            if total > 0 { free * 100 / total } else { 0 },
            ffree,
            files
        ),
        None => outln!(o, "{what}: statvfs failed"),
    }
}

/// B2.6
pub fn storage(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("host/storage.txt");
    let ms = if LINUX { mounts() } else { vec![] };
    space_line(o, "output folder", &ctx.out_dir);
    let mut devices: Vec<String> = Vec::new();
    for d in &ctx.datadirs {
        head(o, &format!("datadir-{} ({})", d.n, r.path_of(&d.path)));
        space_line(o, "free", &d.path);
        if LINUX {
            match mount_of(&ms, &d.path) {
                Some(m) => {
                    let ro = m.opts.split(',').any(|x| x == "ro");
                    outln!(o, "filesystem {} on {} mounted at {}", m.fstype, source_shown(&m.source, &m.fstype), r.path(&m.point));
                    outln!(o, "options {}", m.opts);
                    outln!(o, "read-only: {}", if ro { "YES" } else { "no" });
                    if m.source.starts_with("/dev/") && !devices.contains(&m.source) {
                        devices.push(m.source.clone());
                    }
                }
                None => outln!(o, "mount: not found in /proc/self/mountinfo"),
            }
        } else {
            let p = d.path.to_string_lossy().to_string();
            cmd_block_t(o, "df", &["-k", &p], 10, 64 << 10);
            let m = util::run_cmd("mount", &[], Duration::from_secs(10), 256 << 10);
            let df = util::run_cmd("df", &[&p], Duration::from_secs(10), 64 << 10);
            if let Some(dev) = df.text().lines().nth(1).and_then(|l| l.split_whitespace().next()) {
                for l in m.text().lines().filter(|l| l.starts_with(&format!("{dev} "))) {
                    outln!(o, "mount: {l}");
                }
            }
        }
        fsync_test(ctx, d, o);
    }
    if ctx.datadirs.is_empty() {
        outln!(o, "no data dir found");
    }
    if util::which("smartctl").is_some() {
        for dev in devices {
            head(o, &format!("SMART {dev}"));
            // -n standby: never spin a sleeping disk up; no prompts
            cmd_block_t(o, "smartctl", &["-n", "standby", "-H", "-A", &dev], 15, 256 << 10);
        }
    } else {
        head(o, "SMART");
        outln!(o, "smartctl not installed; skipped");
    }
}

/// R1 b: up to 10 MB in 4 KB write+fdatasync, about 40 s at most
fn fsync_test(ctx: &Ctx, d: &DataDir, o: &mut Out) {
    outln!(o, "-- fsync test");
    if !ctx.allow_fsync {
        outln!(o, "skipped (--no-fsync-test)");
        return;
    }
    if d.running_pid.is_some() {
        outln!(o, "skipped: a node is running on this data dir (the test would compete with it)");
        return;
    }
    if let Some((total, free, _, _)) = util::statvfs(&d.path) {
        let need = (1u64 << 30).max(total / 20);
        if free < need {
            outln!(o, "skipped: less than {} free", util::human(need));
            return;
        }
    }
    let id = ctx
        .out_dir
        .file_name()
        .map(|n| n.to_string_lossy().trim_start_matches("irondivi-diag-").to_string())
        .unwrap_or_else(|| "x".into());
    let path: PathBuf = d.path.join(format!(".irondivi-diag-fsync-{id}"));
    let f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path);
    let mut f = match f {
        Ok(f) => f,
        Err(e) => {
            outln!(o, "could not create the test file: {}", util::io_err(&e));
            return;
        }
    };
    use std::io::Write;
    use std::os::unix::io::AsRawFd;
    let buf = [0x5au8; 4096];
    let mut lat: Vec<f64> = Vec::new();
    let mut err: Option<String> = None;
    let began = Instant::now();
    while lat.len() < 2560 && began.elapsed() < Duration::from_secs(40) {
        let t = Instant::now();
        if let Err(e) = f.write_all(&buf) {
            err = Some(format!("write: {}", util::io_err(&e)));
            break;
        }
        #[cfg(target_os = "linux")]
        let rc = unsafe { libc::fdatasync(f.as_raw_fd()) };
        #[cfg(not(target_os = "linux"))]
        let rc = unsafe { libc::fsync(f.as_raw_fd()) };
        if rc != 0 {
            err = Some(format!("fdatasync: {}", util::io_err(&std::io::Error::last_os_error())));
            break;
        }
        lat.push(t.elapsed().as_secs_f64() * 1000.0);
    }
    drop(f);
    let rm = std::fs::remove_file(&path);
    if lat.is_empty() {
        outln!(o, "no write completed");
    } else {
        let mut s = lat.clone();
        s.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let pct = |q: f64| s[((s.len() as f64 - 1.0) * q).round() as usize];
        outln!(
            o,
            "{} writes of 4 KB ({}) in {:.1} s: p50 {:.2} ms, p99 {:.2} ms, max {:.2} ms{}",
            s.len(),
            util::human(s.len() as u64 * 4096),
            began.elapsed().as_secs_f64(),
            pct(0.5),
            pct(0.99),
            s[s.len() - 1],
            if s.len() < 2560 { " (stopped at the 40 s bound)" } else { "" }
        );
        if !LINUX {
            outln!(o, "(macOS: fsync(2), which does not force the drive cache; F_FULLFSYNC is not tested)");
        }
    }
    if let Some(e) = err {
        outln!(o, "error: {e}");
    }
    if let Err(e) = rm {
        outln!(o, "could not remove the test file: {} (diag removes leftovers at the end)", util::io_err(&e));
    }
}

// ---------------------------------------------------------------- B2.7

struct Entry {
    rel: String,
    is_dir: bool,
    size: u64,
    mtime: i64,
    mode: u32,
    uid: u32,
}

fn walk(root: &Path, dir: &Path, out: &mut Vec<Entry>, wallet: &mut (u64, u64), depth: usize, errors: &mut Vec<String>) {
    if depth > 12 || out.len() > 200_000 {
        return;
    }
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) => {
            errors.push(format!("{}: {}", dir.strip_prefix(root).unwrap_or(dir).display(), util::io_err(&e)));
            return;
        }
    };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
        let rel = p.strip_prefix(root).unwrap_or(&p).to_string_lossy().to_string();
        let top = rel.split('/').next().unwrap_or("");
        if top == "wallet" {
            // §6.1: one total, nothing per file, nothing read
            if md.is_dir() {
                wallet_total(&p, wallet, 0);
            } else {
                wallet.0 += 1;
                wallet.1 += md.len();
            }
            continue;
        }
        out.push(Entry {
            rel: rel.clone(),
            is_dir: md.is_dir(),
            size: md.len(),
            mtime: md.mtime(),
            mode: md.mode(),
            uid: md.uid(),
        });
        if md.is_dir() {
            walk(root, &p, out, wallet, depth + 1, errors);
        }
    }
}

fn wallet_total(dir: &Path, t: &mut (u64, u64), depth: usize) {
    if depth > 8 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(md) = std::fs::symlink_metadata(e.path()) else { continue };
        if md.is_dir() {
            wallet_total(&e.path(), t, depth + 1);
        } else {
            t.0 += 1;
            t.1 += md.len();
        }
    }
}

/// A file name that may say something about the wallet (backups, dumps)
fn wallet_ish(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.contains("wallet") || l.ends_with(".dat") && l != "peers.dat" && l != "banlist.dat" && l != "mncache.dat" && l != "mnpayments.dat" && l != "netfulfilled.dat" && l != "budget.dat" && l != "fee_estimates.dat"
}

fn shown_rel(r: &crate::redact::Redactor, rel: &str) -> String {
    rel.split('/')
        .map(|c| if wallet_ish(c) { r.pseudonym("walletfile", c) } else { c.to_string() })
        .collect::<Vec<_>>()
        .join("/")
}

fn is_temp(name: &str) -> bool {
    name.ends_with(".tmp") || name.ends_with(".temp") || name.ends_with('~') || name.starts_with(".irondivi-diag-fsync-") || name.ends_with(".partial") || name.ends_with(".new") || name.ends_with(".old") && !name.starts_with("LOG")
}

/// B2.7
pub fn inventory(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    for d in &ctx.datadirs {
        o.file(&format!("datadir-{}/inventory.txt", d.n));
        let node_uid = ctx.node_for(d).and_then(|n| n.uid).or(d.owner);
        let owner = |uid: u32| -> String {
            if uid == 0 {
                "root".into()
            } else if Some(uid) == node_uid {
                "node user".into()
            } else {
                r.user(&util::user_name(uid).unwrap_or_else(|| uid.to_string()))
            }
        };
        let mut entries = Vec::new();
        let mut wallet = (0u64, 0u64);
        let mut errors = Vec::new();
        walk(&d.path, &d.path, &mut entries, &mut wallet, 0, &mut errors);
        entries.sort_by(|a, b| a.rel.cmp(&b.rel));

        // RocksDB instances: dirs holding CURRENT
        let dbs: Vec<String> = entries
            .iter()
            .filter(|e| !e.is_dir && (e.rel == "CURRENT" || e.rel.ends_with("/CURRENT")))
            .map(|e| e.rel.trim_end_matches("CURRENT").trim_end_matches('/').to_string())
            .collect();
        let in_db = |rel: &str| -> Option<&String> {
            dbs.iter().filter(|db| db.is_empty() || rel.starts_with(&format!("{db}/"))).max_by_key(|db| db.len())
        };

        head(o, "ownership mismatches (not owned by the node's user)");
        let mut mism = 0;
        if let Some(nu) = node_uid {
            for e in &entries {
                if e.uid != nu {
                    mism += 1;
                    if mism <= 200 {
                        outln!(o, "{}  {}", shown_rel(&r, &e.rel), owner(e.uid));
                    }
                }
            }
            if mism > 200 {
                outln!(o, "... {} more", mism - 200);
            }
            if mism == 0 {
                outln!(o, "none");
            }
        } else {
            outln!(o, "the node's user is not known");
        }

        head(o, "leftover temporaries");
        let temps: Vec<&Entry> = entries.iter().filter(|e| !e.is_dir && is_temp(e.rel.rsplit('/').next().unwrap_or(""))).collect();
        if temps.is_empty() {
            outln!(o, "none");
        }
        for e in temps {
            outln!(o, "{}  {}  {}", shown_rel(&r, &e.rel), util::human(e.size), util::rfc3339(e.mtime));
        }

        head(o, "wallet/ (summarised; nothing in it is read)");
        outln!(o, "{} files, {}", wallet.0, util::human(wallet.1));

        head(o, "RocksDB instances");
        for db in &dbs {
            let (mut n, mut sz, mut sst, mut sst_sz) = (0u64, 0u64, 0u64, 0u64);
            for e in entries.iter().filter(|e| !e.is_dir && in_db(&e.rel) == Some(db)) {
                n += 1;
                sz += e.size;
                if e.rel.ends_with(".sst") {
                    sst += 1;
                    sst_sz += e.size;
                }
            }
            outln!(o, "{}/: {n} files, {}; {sst} SST files, {}", if db.is_empty() { "." } else { db }, util::human(sz), util::human(sst_sz));
        }
        if dbs.is_empty() {
            outln!(o, "none");
        }

        head(o, "every file (RocksDB files summarised above)");
        outln!(o, "{:<6} {:>10} {:<20} {:<14} path", "mode", "size", "mtime", "owner");
        for e in &entries {
            let name = e.rel.rsplit('/').next().unwrap_or("");
            let rocks_file = in_db(&e.rel).is_some()
                && (name.ends_with(".sst") || name.ends_with(".log") || name.ends_with(".blob"));
            if rocks_file {
                continue;
            }
            outln!(
                o,
                "{:<6o} {:>10} {:<20} {:<14} {}{}",
                e.mode & 0o7777,
                if e.is_dir { "-".into() } else { util::human(e.size) },
                util::rfc3339(e.mtime),
                owner(e.uid),
                shown_rel(&r, &e.rel),
                if e.is_dir { "/" } else { "" }
            );
        }
        for err in &errors {
            outln!(o, "unreadable: {err}");
        }

        // OPTIONS and LOG of the chain RocksDB instances (never wallet/)
        for db in &dbs {
            let dir = d.path.join(db);
            let tag = if db.is_empty() { "root".to_string() } else { db.replace('/', "_") };
            let Ok(rd) = std::fs::read_dir(&dir) else { continue };
            let mut names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().to_string()).collect();
            names.sort();
            let newest_opts = names.iter().filter(|n| n.starts_with("OPTIONS-")).last().cloned();
            for n in names {
                let p = dir.join(&n);
                if Some(&n) == newest_opts.as_ref() {
                    o.file(&format!("datadir-{}/rocksdb/{tag}/{n}", d.n));
                    match util::read_bytes_capped(&p, 1 << 20) {
                        Ok(b) => o.write(util::escape_bytes(&b).as_bytes()),
                        Err(e) => outln!(o, "{}", util::io_err(&e)),
                    }
                } else if n == "LOG" || n.starts_with("LOG.old.") {
                    o.file(&format!("datadir-{}/rocksdb/{tag}/{n}", d.n));
                    match util::read_tail(&p, 2 << 20) {
                        Ok((b, cut)) => {
                            if cut {
                                outln!(o, "[cut: the last 2 MB]");
                            }
                            o.write(util::escape_bytes(&b).as_bytes());
                        }
                        Err(e) => outln!(o, "{}", util::io_err(&e)),
                    }
                }
            }
        }
    }
    if ctx.datadirs.is_empty() {
        outln!(o, "no data dir found");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_sources_hidden() {
        assert_eq!(source_shown("nas:/export", "nfs4"), "<network source>");
        assert_eq!(source_shown("/dev/sda1", "ext4"), "/dev/sda1");
    }

    #[test]
    fn wallet_names() {
        assert!(wallet_ish("wallet.dat"));
        assert!(wallet_ish("my-backup.dat"));
        assert!(!wallet_ish("peers.dat"));
        assert!(!wallet_ish("debug.log"));
    }

    #[test]
    fn inventory_never_lists_wallet_files() {
        let t = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(t.path().join("wallet")).unwrap();
        std::fs::write(t.path().join("wallet/000123.sst"), b"x").unwrap();
        std::fs::write(t.path().join("debug.log"), b"x").unwrap();
        let mut e = Vec::new();
        let mut w = (0, 0);
        let mut errs = Vec::new();
        walk(t.path(), t.path(), &mut e, &mut w, 0, &mut errs);
        assert_eq!(w, (1, 1));
        assert!(e.iter().all(|x| !x.rel.starts_with("wallet")));
        assert!(e.iter().any(|x| x.rel == "debug.log"));
    }
}
