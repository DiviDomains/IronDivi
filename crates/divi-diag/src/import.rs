// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B6.4 `irondivi-cli diag --import <folder|->`: turn a folder collected by
//! `contrib/diag.sh` (B1.4) into a package, on any machine where
//! irondivi-cli runs.
//!
//! Every file is unredacted text. The order per file:
//! 1. known values are harvested from the whole folder first (B6.6: host
//!    names from the syslog host column, `_HOSTNAME=`, `Computer`/
//!    `MachineName`, `docker info` `Name:`; user names from `/home/<u>`,
//!    `/Users/<u>`, `C:\Users\<u>`, the `ps` user column and `ls -l` owner
//!    and group columns) and unioned with this machine's own;
//! 2. the step 3 structure rules that need the raw columns: kernel lines
//!    lose the syslog host column and quoted command lines keep only the
//!    program (§6.2 "Kernel lines"), an OOM table keeps only the node's
//!    rows, `ls -l` owners and names and the `ps` user column are replaced;
//! 3. the "Old-log lines" rule on every line ([`oldlog::filter`]);
//! 4. the §6.2 step 2 patterns ([`Redactor::scrub`]): with no wallet known
//!    values, every remaining 64-hex string is pseudonymised and every
//!    address-shaped token masked;
//! 5. the §6.3 final scanner, as for a normal run.
//!
//! The unredacted input is held in memory only: `--import -` reads a tar
//! from stdin and never writes it to disk. A folder that carries the
//! diag.sh marker is deleted once the import has finished (B1.4 container
//! path), unless `--keep-raw`.

use crate::collectors::logs::{mask_quoted_cmdlines, reduce_oom};
use crate::redact::{Known, Redactor};
use crate::scanner::{self, Scanner, Secret};
use crate::{oldlog, runner, tar, util, Options};
use regex::Regex;
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// A single file larger than this is skipped (diag.sh caps its largest copy at 4 MB)
pub const PER_FILE: u64 = 32 << 20;
/// The whole import is held in memory, so it is capped
pub const TOTAL: u64 = 512 << 20;
/// diag.log's first line, written by contrib/diag.sh
pub const MARKER: &str = "collected by contrib/diag.sh";

#[derive(Default)]
pub struct Raw {
    /// (relative name, bytes)
    pub files: Vec<(String, Vec<u8>)>,
    /// (relative name, why)
    pub skipped: Vec<(String, String)>,
}

pub enum Source {
    Folder(PathBuf),
    Stdin,
}

pub struct Report {
    pub out: PathBuf,
    pub left_out: usize,
    pub raw: String,
}

fn safe_rel(rel: &str) -> bool {
    !rel.is_empty() && !rel.starts_with('/') && rel.split('/').all(|c| !c.is_empty() && c != "." && c != "..")
}

fn norm(name: &str) -> String {
    let mut n = name;
    while let Some(r) = n.strip_prefix("./") {
        n = r;
    }
    n.trim_end_matches('/').to_string()
}

/// Regular files only; symbolic links and special files are listed, never followed
pub fn read_folder(root: &Path) -> Result<Raw, String> {
    let md = fs::symlink_metadata(root).map_err(|e| format!("{}: {}", root.display(), util::io_err(&e)))?;
    if !md.is_dir() {
        return Err(format!("{} is not a folder", root.display()));
    }
    let mut raw = Raw::default();
    let mut total = 0u64;
    fn go(root: &Path, dir: &Path, depth: usize, raw: &mut Raw, total: &mut u64) -> Result<(), String> {
        let rd = fs::read_dir(dir).map_err(|e| format!("{}: {}", dir.display(), util::io_err(&e)))?;
        let mut entries: Vec<_> = rd.flatten().collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let p = e.path();
            let rel = p.strip_prefix(root).map(|r| util::escape_bytes(std::os::unix::ffi::OsStrExt::as_bytes(r.as_os_str()))).unwrap_or_default();
            let Ok(md) = fs::symlink_metadata(&p) else {
                raw.skipped.push((rel, "could not be read".into()));
                continue;
            };
            if md.is_dir() {
                if depth >= 16 {
                    raw.skipped.push((rel, "nested more than 16 folders deep".into()));
                } else {
                    go(root, &p, depth + 1, raw, total)?;
                }
            } else if !md.is_file() {
                let why = if md.file_type().is_symlink() { "symbolic link: not followed" } else { "not a regular file" };
                raw.skipped.push((rel, why.into()));
            } else if md.len() > PER_FILE {
                raw.skipped.push((rel, format!("{} bytes, over the {PER_FILE}-byte cap per file", md.len())));
            } else if *total + md.len() > TOTAL {
                raw.skipped.push((rel, format!("over the {TOTAL}-byte cap for the whole import")));
            } else {
                match fs::read(&p) {
                    Ok(d) => {
                        *total += d.len() as u64;
                        raw.files.push((rel, d));
                    }
                    Err(e) => raw.skipped.push((rel, format!("could not be read: {}", util::io_err(&e)))),
                }
            }
        }
        Ok(())
    }
    go(root, root, 0, &mut raw, &mut total)?;
    Ok(raw)
}

/// `tar -cf - . | irondivi-cli diag --import -`
pub fn read_tar<R: Read>(r: &mut R) -> Result<Raw, String> {
    let mut raw = Raw::default();
    for m in tar::read_all(r, PER_FILE, TOTAL)? {
        match m {
            tar::Member::File { name, data } => {
                let n = norm(&name);
                if n.is_empty() {
                    continue;
                }
                if safe_rel(&n) {
                    raw.files.push((n, data));
                } else {
                    raw.skipped.push((n, "a name that leaves the folder".into()));
                }
            }
            tar::Member::Skipped { name, why } => raw.skipped.push((norm(&name), why)),
        }
    }
    Ok(raw)
}

// ------------------------------------------------------------ harvesting

/// System accounts and groups kept as they are in owner columns
fn system_name(n: &str) -> bool {
    n.is_empty()
        || n.bytes().all(|b| b.is_ascii_digit())
        || n.starts_with('_')
        || n.starts_with("systemd-")
        || matches!(
            n,
            "root" | "wheel" | "staff" | "admin" | "users" | "nogroup" | "nobody" | "daemon" | "adm" | "sys" | "bin"
                | "docker" | "everyone" | "messagebus" | "syslog" | "man" | "mail" | "uucp" | "lp" | "www-data"
                | "sudo" | "irondivi" | "divi" | "tty" | "disk" | "utmp" | "shadow" | "input" | "kvm" | "render"
                | "video" | "audio" | "plugdev" | "netdev" | "lxd" | "polkitd" | "sshd" | "ntp" | "chrony"
        )
}

struct Rules {
    home: Regex,
    win: Regex,
    hostname_kv: Regex,
    computer: Regex,
    docker_name: Regex,
    host_col: Regex,
    ls: Regex,
    ps: Regex,
    nfs: Regex,
    secret: Regex,
}

impl Rules {
    fn new() -> Self {
        Rules {
            home: Regex::new(r#"(?:/home/|/Users/)([^/\s:'"\\*$]+)"#).unwrap(),
            win: Regex::new(r#"(?i)\b[a-z]:\\Users\\([^\\\s"':]+)"#).unwrap(),
            hostname_kv: Regex::new(r"_HOSTNAME=([^\s;,]+)").unwrap(),
            computer: Regex::new(r"(?m)^\s*(?:Computer|ComputerName|MachineName)\s*[:=]\s*(\S+)").unwrap(),
            docker_name: Regex::new(r"(?m)^\s*Name:\s*(\S+)").unwrap(),
            // the host column of classic syslog, journalctl short-iso and
            // macOS `log show --style syslog`
            host_col: Regex::new(
                r"^(?:[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d[.\d]*(?:Z|[+-]\d\d:?\d\d)?|\d{4}-\d\d-\d\d \d\d:\d\d:\d\d[.\d]*(?:[+-]\d{4})?) +([^\s\[:]+) ",
            )
            .unwrap(),
            ls: Regex::new(
                r"^([-dlcbpsD][rwxsStT-]{9}[@+.]?\s+\d+\s+)(\S+)(\s+)(\S+)(\s+.*?\s(?:[A-Z][a-z]{2}\s+\d{1,2}|\d{1,2}\s+[A-Z][a-z]{2})\s+(?:\d\d:\d\d|\d{4})\s)(.*)$",
            )
            .unwrap(),
            ps: Regex::new(r"^(\s*\d+\s+)(\S+)(\s.*)$").unwrap(),
            nfs: Regex::new(r"(?m)^([A-Za-z0-9][A-Za-z0-9.-]*):/").unwrap(),
            secret: Regex::new(r"(?m)^\s*(rpcpassword|rpcuser)\s*=\s*(\S+)").unwrap(),
        }
    }
}

/// The lines of host.txt's `ps` section
fn ps_section(text: &str) -> impl Iterator<Item = (usize, &str)> {
    let mut on = false;
    text.lines().enumerate().filter(move |(_, l)| {
        if l.starts_with("== ") {
            on = l.starts_with("== processes named irondivi");
            return false;
        }
        on
    })
}

fn is_kernel(rel: &str) -> bool {
    rel.starts_with("kernel/")
}

struct Harvest {
    known: Known,
    secrets: Vec<Secret>,
}

fn harvest(raw: &Raw, rules: &Rules) -> Harvest {
    let mut hosts = BTreeSet::new();
    let mut users = BTreeSet::new();
    let mut secrets = Vec::new();
    for (rel, data) in &raw.files {
        let text = util::escape_bytes(data);
        for c in rules.home.captures_iter(&text) {
            let u = &c[1];
            if !matches!(u, "Shared" | "Guest") && !system_name(u) {
                users.insert(u.to_string());
            }
        }
        for c in rules.win.captures_iter(&text) {
            let u = &c[1];
            if !matches!(u.to_ascii_lowercase().as_str(), "public" | "default" | "all users" | "default user") {
                users.insert(u.to_string());
            }
        }
        for re in [&rules.hostname_kv, &rules.computer] {
            for c in re.captures_iter(&text) {
                hosts.insert(c[1].trim_matches('"').to_string());
            }
        }
        if text.contains("Server Version:") {
            for c in rules.docker_name.captures_iter(&text) {
                hosts.insert(c[1].to_string());
            }
        }
        for c in rules.nfs.captures_iter(&text) {
            hosts.insert(c[1].to_string());
        }
        for c in rules.secret.captures_iter(&text) {
            let v = c[2].trim_matches('"').to_string();
            let common = &c[1] == "rpcuser" && matches!(v.as_str(), "divi" | "irondivi" | "user" | "admin" | "root");
            if !common {
                secrets.push(Secret { value: v, label: format!("the {} in an imported file", &c[1]) });
            }
        }
        for l in text.lines() {
            if is_kernel(rel) {
                if let Some(c) = rules.host_col.captures(l) {
                    hosts.insert(c[1].to_string());
                }
            }
            if let Some(c) = rules.ls.captures(l) {
                for u in [&c[2], &c[4]] {
                    if !system_name(u) {
                        users.insert(u.to_string());
                    }
                }
            }
        }
        if rel == "host/host.txt" {
            for (_, l) in ps_section(&text) {
                if let Some(c) = rules.ps.captures(l) {
                    if !system_name(&c[2]) {
                        users.insert(c[2].to_string());
                    }
                }
            }
        }
    }
    hosts.retain(|h| h != "localhost" && h.len() >= 2);
    let mut known = crate::discovery::known_values();
    known.hostnames.extend(hosts);
    known.users.extend(users);
    Harvest { known, secrets }
}

// ------------------------------------------------------------ rendering

/// Output names: diag.sh's own names are kept, anything else goes through
/// the path rule
fn out_rel(rel: &str, r: &Redactor) -> String {
    rel.split('/')
        .map(|c| {
            let ours = matches!(
                c,
                "host" | "host.txt" | "binaries.txt" | "inventory.txt" | "logs" | "mirrors" | "kernel" | "kernel.txt"
                    | "README.txt" | "logs-errors.txt" | "diag.log"
            ) || c.strip_prefix("datadir-").or_else(|| c.strip_prefix("root-")).is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
                || ["runs.log", "crash.log", "events.log", "chain-events.log", "health.log", "rpc-methods", "rpc-aggregate", "debug.log"]
                    .iter()
                    .any(|p| c.starts_with(p))
                // A-file rotations and incident/startup files are named by time
                || (c.len() <= 64 && c.bytes().all(|b| b.is_ascii_digit() || b"-T:.Z_".contains(&b) || b.is_ascii_lowercase()) && c.bytes().filter(|b| b.is_ascii_digit()).count() >= 8);
            if ours {
                c.to_string()
            } else {
                r.path(c)
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn render(rel: &str, data: &[u8], r: &Redactor, rules: &Rules) -> String {
    let text = util::escape_bytes(data);
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if is_kernel(rel) {
        lines = lines
            .into_iter()
            .map(|l| {
                let l = match rules.host_col.captures(&l) {
                    Some(c) => {
                        let m = c.get(1).unwrap();
                        format!("{}{}", &l[..m.start()], &l[m.end() + 1..])
                    }
                    None => l,
                };
                mask_quoted_cmdlines(&l)
            })
            .collect();
        lines = reduce_oom(lines, &[]);
    }
    let ps_lines: BTreeSet<usize> = if rel == "host/host.txt" { ps_section(&text).map(|(i, _)| i).collect() } else { BTreeSet::new() };
    let owner = |u: &str| if system_name(u) { u.to_string() } else { r.user(u) };
    for (i, l) in lines.iter_mut().enumerate() {
        if let Some(c) = rules.ls.captures(l) {
            let name = &c[6];
            let name = match name.split_once(" -> ") {
                Some((a, b)) => format!("{} -> {}", r.path(a), r.path(b)),
                None => r.path(name),
            };
            *l = format!("{}{}{}{}{}{}", &c[1], owner(&c[2]), &c[3], owner(&c[4]), &c[5], name);
        } else if ps_lines.contains(&i) {
            if let Some(c) = rules.ps.captures(l) {
                *l = format!("{}{}{}", &c[1], owner(&c[2]), &c[3]);
            }
        }
    }
    let mut joined = lines.join("\n");
    joined.push('\n');
    r.scrub(&oldlog::filter(&joined, r).render())
}

// ------------------------------------------------------------ the import

struct Imp<'a> {
    out: PathBuf,
    id: String,
    red: &'a Redactor,
    started: i64,
    source: String,
    marker: Option<String>,
    imported: Vec<(String, String, usize)>,
    skipped: Vec<(String, String)>,
    known_counts: (usize, usize),
    left_out: Vec<(String, String)>,
    scanned: bool,
    raw_note: String,
    log: Vec<String>,
}

impl Imp<'_> {
    fn note(&mut self, msg: &str) {
        self.log.push(format!("{} {}", util::rfc3339(util::now_secs()), self.red.scrub(msg)));
        let mut s = self.log.join("\n");
        s.push('\n');
        write_file(&self.out, "diag.log", s.as_bytes());
    }

    fn summary(&self) {
        let mut s = String::new();
        s.push_str(&format!("IronDivi diagnostics — irondivi-cli diag {} --import (B6.4)\n", crate::VERSION));
        s.push_str(&format!("Local id: {} (a ticket is issued only when the package is sent)\n", self.id));
        s.push_str(&format!("Imported: {}   from: {}\n", util::rfc3339(self.started), self.source));
        match &self.marker {
            Some(m) => s.push_str(&format!("Source: {}\n", self.red.scrub(m))),
            None => s.push_str("Source: no contrib/diag.sh marker in diag.log; every file was imported as unredacted text all the same\n"),
        }
        s.push_str(
            "\nKnown values unavailable: the collecting machine's node and wallet were not asked (§6.2 step 1), \
so every 64-hex string is pseudonymised and every address-shaped token masked.\n",
        );
        s.push_str(&format!(
            "Known values parsed from the folder (B6.6): {} host name(s), {} user name(s) (with this machine's own)\n",
            self.known_counts.0, self.known_counts.1
        ));
        s.push_str("\n== Imported (B6.4) ==\n");
        for (orig, outrel, lines) in &self.imported {
            if orig == outrel {
                s.push_str(&format!("imported/{outrel} ({lines} lines)\n"));
            } else {
                s.push_str(&format!("imported/{outrel} ({lines} lines; the name was redacted)\n"));
            }
        }
        if !self.skipped.is_empty() {
            s.push_str("\n== Not imported ==\n");
            for (f, why) in &self.skipped {
                s.push_str(&format!("{}: {why}\n", out_rel(f, self.red)));
            }
        }
        if !self.left_out.is_empty() {
            s.push_str("\n== Left out by the final scan (§6.3) ==\n");
            for (f, why) in &self.left_out {
                s.push_str(&format!("{f}: {why}\n"));
            }
        }
        if !self.raw_note.is_empty() {
            s.push_str(&format!("\n== The unredacted input ==\n{}\n", self.red.scrub(&self.raw_note)));
        }
        s.push_str(if self.scanned {
            "\nThis folder has been through diag's import redaction (§6.2, B6.4) and final scan (§6.3), and was not sent anywhere.\n"
        } else {
            "\nThis folder has been through diag's import redaction (§6.2, B6.4) and was not sent anywhere.\n"
        });
        let tmp = self.out.join(".00-SUMMARY.tmp");
        if let Ok(mut f) = OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp) {
            let _ = f.write_all(s.as_bytes());
            let _ = f.sync_data();
            let _ = fs::rename(&tmp, self.out.join("00-SUMMARY.txt"));
        }
    }

    fn manifest(&self) {
        let mut files = Vec::new();
        scanner::walk(&self.out, &self.out, &mut files);
        files.sort();
        let mut m = String::from("# path\tsize\tsha256\tcollector\n");
        m.push_str("# imported from a contrib/diag.sh folder: every file went through the B6.4 import redaction\n");
        for (f, why) in &self.left_out {
            m.push_str(&format!("# left out: {f} — {why}\n"));
        }
        for rel in files {
            if rel == "02-manifest.txt" || rel.starts_with('.') {
                continue;
            }
            let p = self.out.join(&rel);
            let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let h = util::sha256_file(&p).unwrap_or_else(|e| util::io_err(&e));
            let who = if rel.starts_with("imported/") { "import" } else { "diag" };
            m.push_str(&format!("{rel}\t{size}\t{h}\t{who}\n"));
        }
        write_file(&self.out, "02-manifest.txt", m.as_bytes());
    }
}

fn write_file(root: &Path, rel: &str, data: &[u8]) -> bool {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        if fs::DirBuilder::new().recursive(true).mode(0o700).create(parent).is_err() {
            return false;
        }
    }
    match OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&p) {
        Ok(mut f) => f.write_all(data).is_ok(),
        Err(_) => false,
    }
}

/// Remove the files that were imported, then the folders they leave empty.
/// Nothing else is touched: a file diag.sh did not write stays, and so does
/// the folder holding it.
fn delete_raw(root: &Path, rels: &[String]) -> String {
    let mut failed = 0;
    let mut dirs = BTreeSet::new();
    for rel in rels {
        if fs::remove_file(root.join(rel)).is_err() {
            failed += 1;
        }
        let mut p = Path::new(rel.as_str()).parent();
        while let Some(d) = p.filter(|d| !d.as_os_str().is_empty()) {
            dirs.insert(d.to_path_buf());
            p = d.parent();
        }
    }
    let mut dirs: Vec<PathBuf> = dirs.into_iter().collect();
    dirs.sort_by_key(|d| std::cmp::Reverse(d.components().count()));
    for d in dirs {
        let _ = fs::remove_dir(root.join(d));
    }
    let gone = fs::remove_dir(root).is_ok();
    match (gone, failed) {
        (true, _) => format!("deleted the unredacted folder {} ({} files) now that the import has finished", root.display(), rels.len()),
        (false, 0) => format!(
            "deleted the {} unredacted files diag.sh wrote in {}; the folder holds other files, so it was left",
            rels.len(),
            root.display()
        ),
        (false, n) => format!("deleted the unredacted files in {} except {n} that could not be removed: remove the folder by hand", root.display()),
    }
}

/// The import itself, given the files already in memory
pub fn import(raw: Raw, source: Source, o: &Options) -> Result<Report, String> {
    unsafe { libc::umask(0o077) };
    let rules = Rules::new();
    let h = harvest(&raw, &rules);
    let salt = Redactor::new_salt();
    let red = Redactor::new(salt, &h.known);

    let id = runner::local_id();
    let (out, _tried) = runner::create_out(o, &id, &crate::ctx::Ctx::default())?;
    let marker = raw
        .files
        .iter()
        .find(|(n, _)| n == "diag.log")
        .and_then(|(_, d)| util::escape_bytes(d).lines().next().map(str::to_string))
        .filter(|l| l.starts_with(MARKER));
    let src_name = match &source {
        Source::Folder(p) => red.path_of(p),
        Source::Stdin => "a tar archive on stdin (never written to disk)".into(),
    };
    let mut imp = Imp {
        out: out.clone(),
        id,
        red: &red,
        started: util::now_secs(),
        source: src_name,
        marker,
        imported: Vec::new(),
        skipped: raw.skipped.clone(),
        known_counts: (h.known.hostnames.len(), h.known.users.len()),
        left_out: Vec::new(),
        scanned: false,
        raw_note: String::new(),
        log: Vec::new(),
    };
    imp.note(&format!("import of {} files ({} not imported)", raw.files.len(), raw.skipped.len()));

    let mut used = BTreeSet::new();
    for (rel, data) in &raw.files {
        let mut o_rel = out_rel(rel, &red);
        while !used.insert(o_rel.clone()) {
            o_rel.push_str(".dup");
        }
        let text = render(rel, data, &red, &rules);
        let lines = text.lines().count();
        if !write_file(&out, &format!("imported/{o_rel}"), text.as_bytes()) {
            imp.skipped.push((rel.clone(), "could not be written to the package".into()));
            continue;
        }
        imp.imported.push((rel.clone(), o_rel, lines));
    }
    imp.note(&format!("redacted {} files into imported/", imp.imported.len()));
    imp.summary();

    // §6.3 final scan
    imp.scanned = true;
    let sc = Scanner::new(&red, &h.secrets, &salt);
    for round in 0..4 {
        let hits = sc.scan_folder(&out);
        if hits.is_empty() {
            break;
        }
        for hit in hits {
            let _ = fs::remove_file(out.join(&hit.file));
            eprintln!("irondivi-cli diag: left out {} (line {}): {}", hit.file, hit.line, hit.reason);
            imp.left_out.push((hit.file, format!("line {}: {}", hit.line, hit.reason)));
        }
        if round < 3 {
            imp.summary();
        }
    }
    imp.note(&format!("final scan: {} file(s) left out", imp.left_out.len()));

    // B1.4: the raw folder goes once the import has finished
    if let Source::Folder(root) = &source {
        imp.raw_note = if o.keep_raw {
            format!("kept the unredacted folder {} (--keep-raw): delete it yourself once the package is sent", root.display())
        } else if imp.marker.is_none() {
            format!("kept {}: it does not carry the contrib/diag.sh marker, so diag does not delete it", root.display())
        } else {
            let rels: Vec<String> = raw.files.iter().map(|(n, _)| n.clone()).collect();
            delete_raw(root, &rels)
        };
        let n = imp.raw_note.clone();
        imp.note(&n);
    }
    imp.summary();
    imp.manifest();
    let raw_note = imp.raw_note.clone();
    Ok(Report { out, left_out: imp.left_out.len(), raw: raw_note })
}

/// `irondivi-cli diag --import <folder|->`
pub fn import_main(src: &str, o: &Options) -> i32 {
    let (raw, source) = if src == "-" {
        if util::is_tty() {
            eprintln!("irondivi-cli diag: --import - reads a tar archive on stdin, and stdin is a terminal");
            return crate::EX_USAGE;
        }
        match read_tar(&mut std::io::stdin().lock()) {
            Ok(r) => (r, Source::Stdin),
            Err(e) => {
                eprintln!("irondivi-cli diag: --import -: {e}; nothing was written");
                return 1;
            }
        }
    } else {
        let p = PathBuf::from(src);
        match read_folder(&p) {
            Ok(r) => (r, Source::Folder(fs::canonicalize(&p).unwrap_or(p))),
            Err(e) => {
                eprintln!("irondivi-cli diag: --import: {e}");
                return 1;
            }
        }
    };
    if raw.files.is_empty() {
        eprintln!("irondivi-cli diag: --import: no files to import ({} skipped); nothing was written", raw.skipped.len());
        return 1;
    }
    match import(raw, source, o) {
        Ok(rep) => {
            println!("irondivi-cli diag: imported into {} (mode 0700). Start with 00-SUMMARY.txt.", rep.out.display());
            if rep.left_out > 0 {
                println!("irondivi-cli diag: the final scan left out {} file(s); 00-SUMMARY.txt says why.", rep.left_out);
            }
            if !rep.raw.is_empty() {
                println!("irondivi-cli diag: {}", rep.raw);
            }
            0
        }
        Err(e) => {
            eprintln!("irondivi-cli diag: --import: {e}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANARY_HOST: &str = "canaryhostqx";
    const CANARY_USER: &str = "canaryuserqx";
    const CANARY_PW: &str = "canarypwQX7781";
    const CANARY_ARG: &str = "canaryargqx";
    const CANARY_ADDR: &str = "DCanaryAddrQx123456789abcdefghijkm";
    const CANARY_HEX: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";
    const CANARY_IP: &str = "203.0.113.77";
    const CANARY_DIR: &str = "canarydirqx";

    fn folder(d: &Path) {
        let w = |rel: &str, s: String| {
            let p = d.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, s).unwrap();
        };
        w(
            "diag.log",
            format!(
                "{MARKER} (docs/plans/diag.md B1.4) at 2026-10-31T00:00:00Z\nNOT REDACTED: run irondivi-cli diag --import\ndatadir-1: /home/{CANARY_USER}/.irondivi\n"
            ),
        );
        w(
            "host/host.txt",
            format!(
                "== uname (no nodename)\nLinux 6.8.0 #1 SMP x86_64\n== disk\nFilesystem 1K-blocks Used Available Use% Mounted on\n/dev/sda1 100 50 50 50% /srv/{CANARY_DIR}\n== processes named irondivi\n  4242 {CANARY_USER}  01:00:00 123456 irondivid\n"
            ),
        );
        w(
            "datadir-1/inventory.txt",
            format!(
                "path: /home/{CANARY_USER}/.irondivi\ndrwx------  5 {CANARY_USER} {CANARY_USER} 4096 Oct 30 12:00 /home/{CANARY_USER}/.irondivi\n-rw-------  1 {CANARY_USER} {CANARY_USER}   12 Oct 30 12:00 {CANARY_DIR}.dat\n"
            ),
        );
        w(
            "datadir-1/logs/diag/runs.log",
            format!(
                "2026-10-30T10:00:00Z start pid=4242 datadir=/home/{CANARY_USER}/.irondivi host={CANARY_HOST} peer={CANARY_IP}:51472\n2026-10-30T10:00:01Z note rpcpassword={CANARY_PW} addr {CANARY_ADDR} tx {CANARY_HEX}\n"
            ),
        );
        w(
            "datadir-1/logs/debug.log",
            format!(
                "2026-10-27T01:00:00.000Z DEBUG divi_network::sync: Received block {CANARY_HEX} from peer 7\n2026-10-28T01:00:04.000Z  INFO irondivid: Listening on port 51472\n"
            ),
        );
        w(
            "kernel/kernel.txt",
            format!(
                "== journalctl -k (filtered)\nOct 30 12:00:00 {CANARY_HOST} kernel: ptrace attach of \"python3 -I /x/{CANARY_ARG} {CANARY_ARG}\"[123] was attempted by \"cat {CANARY_ARG}\"[456]\n2026-10-30T12:00:00+0000 {CANARY_HOST} kernel: irondivid[4242]: segfault at 0 ip 0 sp 0\n"
            ),
        );
    }

    fn all_text(root: &Path) -> String {
        let mut files = Vec::new();
        scanner::walk(root, root, &mut files);
        files.iter().map(|f| format!("{f}\n{}", String::from_utf8_lossy(&fs::read(root.join(f)).unwrap()))).collect()
    }

    fn check(out: &Path) {
        let t = all_text(out);
        for c in [CANARY_HOST, CANARY_USER, CANARY_PW, CANARY_ARG, CANARY_ADDR, CANARY_HEX, CANARY_IP, CANARY_DIR] {
            assert!(!t.contains(c), "canary {c} survived:\n{t}");
        }
        let s = fs::read_to_string(out.join("00-SUMMARY.txt")).unwrap();
        assert!(s.contains("Known values unavailable"), "{s}");
        assert!(s.contains("final scan (§6.3)"), "{s}");
        assert!(s.contains("imported/datadir-1/logs/diag/runs.log"), "{s}");
        let k = fs::read_to_string(out.join("imported/kernel/kernel.txt")).unwrap();
        assert!(k.contains("\"python3 <args>\"[123]"), "{k}");
        assert!(k.contains("Oct 30 12:00:00 kernel:"), "{k}");
        assert!(scanner::verify_sha(out).unwrap().is_empty());
        let m = fs::read_to_string(out.join("02-manifest.txt")).unwrap();
        assert!(m.contains("imported/datadir-1/logs/diag/runs.log\t"), "{m}");
        assert!(m.contains("\timport\n"), "{m}");
    }

    /// §6.3 canary (e): a diag.sh folder imported on a different machine
    #[test]
    fn canary_e_folder_import() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("raw");
        fs::create_dir(&src).unwrap();
        folder(&src);
        fs::write(src.join("not-from-diag.txt"), "x").unwrap();
        let out = t.path().join("pkg");
        let o = Options { out: Some(out.clone()), ..Default::default() };
        let raw = read_folder(&src).unwrap();
        let rep = import(raw, Source::Folder(src.clone()), &o).unwrap();
        check(&rep.out);
        // the stray file was imported too, so the folder is gone entirely
        assert!(!src.exists(), "{}", rep.raw);
        assert_eq!(rep.left_out, 0);
    }

    #[test]
    fn canary_e_tar_import_and_keep_raw() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("raw");
        fs::create_dir(&src).unwrap();
        folder(&src);
        let raw = read_folder(&src).unwrap();
        let mut w = tar::Writer::new(Vec::new());
        for (n, d) in &raw.files {
            w.file(&format!("./{n}"), d, 0).unwrap();
        }
        let bytes = w.finish().unwrap();
        let out = t.path().join("pkg");
        let o = Options { out: Some(out.clone()), ..Default::default() };
        let raw2 = read_tar(&mut bytes.as_slice()).unwrap();
        assert_eq!(raw2.files.len(), raw.files.len());
        let rep = import(raw2, Source::Stdin, &o).unwrap();
        check(&rep.out);
        assert!(src.exists());

        let out2 = t.path().join("pkg2");
        let o2 = Options { out: Some(out2), keep_raw: true, ..Default::default() };
        let rep2 = import(read_folder(&src).unwrap(), Source::Folder(src.clone()), &o2).unwrap();
        assert!(src.join("diag.log").exists(), "{}", rep2.raw);
    }

    #[test]
    fn no_marker_is_never_deleted_and_symlinks_not_followed() {
        let t = tempfile::tempdir().unwrap();
        let src = t.path().join("raw");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), "hello /home/someoneqx/x\n").unwrap();
        fs::write(t.path().join("secret.txt"), "outside").unwrap();
        std::os::unix::fs::symlink(t.path().join("secret.txt"), src.join("link")).unwrap();
        let raw = read_folder(&src).unwrap();
        assert_eq!(raw.files.len(), 1);
        assert_eq!(raw.skipped[0].0, "link");
        let o = Options { out: Some(t.path().join("pkg")), ..Default::default() };
        let rep = import(raw, Source::Folder(src.clone()), &o).unwrap();
        assert!(src.join("a.txt").exists());
        assert!(rep.raw.contains("marker"));
        let a = fs::read_to_string(rep.out.join("imported").join(out_rel("a.txt", &Redactor::new([0; 32], &Known::default())))).ok();
        // a.txt is not one of diag.sh's names, so its name is redacted too
        assert!(a.is_none());
        assert!(!all_text(&rep.out).contains("someoneqx"));
    }

    #[test]
    fn ls_and_ps_columns() {
        let rules = Rules::new();
        let r = Redactor::new([1; 32], &Known::default());
        let t = render(
            "datadir-1/inventory.txt",
            b"drwxr-x---+ 2 bobqx staff 64 Oct 30 12:00 mywallets -> /Users/bobqx/x\n-rw-r--r--  1 root  wheel  3 30 Oct  2025 ok\n",
            &r,
            &rules,
        );
        assert!(!t.contains("bobqx") && !t.contains("mywallets"), "{t}");
        assert!(t.contains(" staff ") && t.contains("root  wheel"), "{t}");
        let p = render("host/host.txt", b"== processes named irondivi\n  12 carolqx 01:00 5 irondivid\n", &r, &rules);
        assert!(!p.contains("carolqx") && p.contains("irondivid"), "{p}");
    }
}
