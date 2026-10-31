// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! §8: preview and consent.
//!
//! - §8.1 the user's own report, asked before collecting (or read from
//!   `--report-file`), redacted like every other file;
//! - §8.3 the review: the summary, then a menu to list, view, exclude and
//!   include files, and `send`, which re-checks the folder against its
//!   manifest, runs the §6.3 scanner again and sends only on the full word
//!   `yes`;
//! - §8.4 the offline path only. The §9 receiver's hosting is an open
//!   decision, so this build never contacts any server. After `yes` the
//!   files and their manifest are packed as a tar, compressed with zstd and
//!   encrypted with `age` to the developer's key ([`DEV_KEY`]), and the
//!   result is written beside the folder as `<folder>.age` for the user to
//!   send by hand. Nothing unencrypted is ever written beside the folder. A
//!   build with no key ([`DEV_KEY`] `None`) stops after `yes` and writes
//!   nothing.
//!
//! R2: with no terminal nothing is ever sent, whatever the flags. A review
//! writes `preview.ok` (the file list with each file's SHA-256, and the
//! files the user excluded); `--send <folder>` reads it back, names every
//! file changed since, and shows the review again before any `yes`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use crate::redact::Redactor;
use crate::scanner::{self, Scanner, Secret};
use crate::{discovery, oldlog, util, Options};

pub const REPORT: &str = "01-user-report.txt";
pub const MANIFEST: &str = "02-manifest.txt";
pub const SUMMARY: &str = "00-SUMMARY.txt";
pub const PREVIEW_OK: &str = "preview.ok";

/// §8.4: the developer's `age` recipient and its fingerprint
#[derive(Clone, Copy, Debug)]
pub struct DevKey {
    /// an `age` X25519 recipient, `age1…`
    pub recipient: &'static str,
    /// the first 16 hex characters of the SHA-256 of `recipient`, printed
    /// at send so the user can check it against the published one
    pub fingerprint: &'static str,
}

/// The one place the developer's public key lives. The private half is
/// kept in the developer's 1Password, never in this tree.
pub const DEV_KEY: Option<DevKey> = Some(DevKey {
    recipient: "age10r8rlmzg5c3n8c0cslzzpa9vjq879pq32fghv2skmfu3twzl4vmqt7lq0j",
    fingerprint: "9274ffc0368679fe",
});

/// zstd level for the package: well compressed, still quick on a Pi
const ZSTD_LEVEL: i32 = 12;

/// §8.3 step 1, said always (adversarial AC3, privacy N3)
pub const BY_HAND: &str = "A debug.log or crash.log you send by hand, outside this package, is not \
filtered: it can show which blocks and transactions are this wallet's.";

pub const QUESTIONS: [&str; 5] = [
    "What did you see? (Paste any error text; end with an empty line.)",
    "When did it start, roughly? (Date and time, or \"after I did X\".)",
    "What changed before it started? (Upgrade, new config, moved the data dir, new machine or \
     container, power cut, anything.)",
    "What commands did you run around then?",
    "Anything else?",
];

/// Most of a report file that is read; the rest is cut
const REPORT_CAP: u64 = 1 << 20;

/// The terminal, or a script of it in tests
pub struct Io<'a> {
    pub inp: &'a mut dyn BufRead,
    pub out: &'a mut dyn Write,
    /// a real terminal: `$PAGER` may run
    pub tty: bool,
}

impl Io<'_> {
    fn say(&mut self, s: &str) {
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }

    /// One line, without its newline; `None` at end of input
    fn ask(&mut self, prompt: &str) -> Option<String> {
        self.say(prompt);
        let mut l = String::new();
        match self.inp.read_line(&mut l) {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(l.trim_end_matches(['\n', '\r']).to_string()),
        }
    }
}

// ------------------------------------------------------- §8.1 the report

/// Ask the five questions; answer 1 runs to an empty line
pub fn ask_report(io: &mut Io) -> [String; 5] {
    let mut a: [String; 5] = Default::default();
    io.say(
        "\nBefore diag collects anything: five questions about the problem (§8.1). Leave any \
         of them empty with Enter. Your answers are redacted like every other file.\n",
    );
    for (i, q) in QUESTIONS.iter().enumerate() {
        if i == 0 {
            io.say(&format!("\n{}. {q}\n", i + 1));
            let mut lines = Vec::new();
            while let Some(l) = io.ask("> ") {
                if l.trim().is_empty() {
                    break;
                }
                lines.push(l);
            }
            a[0] = lines.join("\n");
        } else {
            match io.ask(&format!("\n{}. {q}\n> ", i + 1)) {
                Some(l) => a[i] = l.trim().to_string(),
                None => break,
            }
        }
    }
    a
}

/// `--report-file`: a line `## N` (N = 1..5) starts answer N; text before
/// the first such line is answer 1
pub fn parse_report_file(text: &str) -> [String; 5] {
    let mut a: [Vec<&str>; 5] = Default::default();
    let mut cur = 0;
    for l in text.lines() {
        let t = l.trim();
        if let Some(n) = t.strip_prefix("## ").and_then(|n| n.trim().parse::<usize>().ok()) {
            if (1..=5).contains(&n) {
                cur = n - 1;
                continue;
            }
        }
        a[cur].push(l);
    }
    a.map(|v| v.join("\n").trim().to_string())
}

/// `01-user-report.txt`, through the §6.2 old-log rule and patterns
pub fn render_report(a: &[String; 5], how: &str, r: &Redactor) -> String {
    let mut s = format!("The user's own report (§8.1). {how}\n");
    for (i, q) in QUESTIONS.iter().enumerate() {
        let ans = if a[i].is_empty() { "(no answer)" } else { a[i].as_str() };
        s.push_str(&format!("\n{}. {q}\n{ans}\n", i + 1));
    }
    r.scrub(&oldlog::filter(&s, r).render())
}

/// The redacted answer 2, for the summary beside the run table
pub fn reported_start(report: &str) -> Option<String> {
    let after = report.split_once(&format!("\n2. {}\n", QUESTIONS[1]))?.1;
    let first = after.lines().next()?.trim();
    if first.is_empty() || first == "(no answer)" {
        return None;
    }
    Some(first.chars().take(200).collect())
}

/// The report text for this run: from `--report-file`, the terminal, or a
/// note that the questions were skipped
pub fn user_report(o: &Options, r: &Redactor) -> String {
    if let Some(p) = &o.report_file {
        let read = fs::File::open(p).and_then(|f| {
            let mut v = Vec::new();
            io::Read::read_to_end(&mut io::Read::take(f, REPORT_CAP), &mut v).map(|_| v)
        });
        return match read {
            Ok(v) => render_report(&parse_report_file(&String::from_utf8_lossy(&v)), "Answers read from --report-file.", r),
            Err(e) => render_report(
                &Default::default(),
                &format!("--report-file could not be read ({}); no answers.", e.kind()),
                r,
            ),
        };
    }
    if !util::is_tty() {
        return render_report(&Default::default(), "No terminal: the questions were skipped.", r);
    }
    let stdin = io::stdin();
    let mut inp = stdin.lock();
    let mut out = io::stdout();
    let mut t = Io { inp: &mut inp, out: &mut out, tty: true };
    let a = ask_report(&mut t);
    render_report(&a, "Answers typed at the terminal.", r)
}

// ------------------------------------------------------ the manifest

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub rel: String,
    pub size: u64,
    pub sha: String,
    pub collector: String,
}

pub fn read_manifest(root: &Path) -> Result<(Vec<String>, Vec<Entry>), String> {
    let m = fs::read_to_string(root.join(MANIFEST)).map_err(|e| format!("{MANIFEST}: {}", e.kind()))?;
    let mut head = Vec::new();
    let mut v = Vec::new();
    for l in m.lines() {
        if l.starts_with('#') {
            head.push(l.to_string());
            continue;
        }
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() >= 3 {
            v.push(Entry {
                rel: f[0].into(),
                size: f[1].parse().unwrap_or(0),
                sha: f[2].into(),
                collector: f.get(3).unwrap_or(&"diag").to_string(),
            });
        }
    }
    Ok((head, v))
}

fn manifest_text(head: &[String], entries: &[Entry], extra: &[String]) -> String {
    let mut s = String::new();
    for h in head.iter().chain(extra) {
        s.push_str(h);
        s.push('\n');
    }
    for e in entries {
        s.push_str(&format!("{}\t{}\t{}\t{}\n", e.rel, e.size, e.sha, e.collector));
    }
    s
}

fn write_private(path: &Path, data: &[u8]) -> io::Result<()> {
    let tmp = path.with_file_name(format!(".{}.tmp", path.file_name().and_then(|n| n.to_str()).unwrap_or("x")));
    {
        let mut f = fs::OpenOptions::new().create(true).write(true).truncate(true).mode(0o600).open(&tmp)?;
        f.write_all(data)?;
        f.sync_data()?;
    }
    fs::rename(&tmp, path)
}

/// One line saying what a file is for (§8.3 step 3)
pub fn why(collector: &str) -> String {
    match collector {
        "import" => "imported from contrib/diag.sh (B6.4)".into(),
        "user" => "your own report (§8.1)".into(),
        "user-added" => "a file you added during the review".into(),
        "diag" => "diag's own summary and log".into(),
        "attach" => "attached by you (B6.6)".into(),
        "rpc" => "RPC calls you named (B6.5)".into(),
        "capture" => "samples every 10 s while the capture ran (B6.1)".into(),
        "observed" => "observed start of irondivid (B3)".into(),
        c => crate::collectors::ALL
            .iter()
            .find(|s| s.name == c)
            .map(|s| format!("{} {}", s.id, s.what))
            .unwrap_or_else(|| c.to_string()),
    }
}

// ------------------------------------------------------- preview.ok (R2)

#[derive(Default, Debug, PartialEq)]
pub struct Preview {
    pub files: BTreeMap<String, String>,
    pub excluded: BTreeSet<String>,
}

fn digest(files: &BTreeMap<String, String>) -> String {
    let mut h = Sha256::new();
    for (rel, sha) in files {
        h.update(format!("{rel}\t{sha}\n").as_bytes());
    }
    hex::encode(h.finalize())
}

pub fn write_preview(root: &Path, p: &Preview) -> io::Result<()> {
    let mut s = String::from("# preview.ok: written by irondivi-cli diag at the end of a review (R2); never sent\n");
    s.push_str(&format!("digest\t{}\n", digest(&p.files)));
    for (rel, sha) in &p.files {
        s.push_str(&format!("file\t{rel}\t{sha}\n"));
    }
    for rel in &p.excluded {
        s.push_str(&format!("excluded\t{rel}\n"));
    }
    write_private(&root.join(PREVIEW_OK), s.as_bytes())
}

/// `None` when absent; an error when its digest does not match its list
pub fn read_preview(root: &Path) -> Result<Option<Preview>, String> {
    let s = match fs::read_to_string(root.join(PREVIEW_OK)) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{PREVIEW_OK}: {}", e.kind())),
    };
    let mut p = Preview::default();
    let mut d = None;
    for l in s.lines() {
        let f: Vec<&str> = l.split('\t').collect();
        match f.as_slice() {
            ["digest", h] => d = Some(h.to_string()),
            ["file", rel, sha] => {
                p.files.insert(rel.to_string(), sha.to_string());
            }
            ["excluded", rel] => {
                p.excluded.insert(rel.to_string());
            }
            _ => {}
        }
    }
    if d.as_deref() != Some(digest(&p.files).as_str()) {
        return Err(format!("{PREVIEW_OK} does not match its own file list"));
    }
    Ok(Some(p))
}

// ------------------------------------------------------------ §8.3 menu

#[derive(Debug, PartialEq)]
pub enum Cmd {
    List,
    View(usize),
    Exclude(usize),
    Include(usize),
    Edit,
    Send,
    Quit,
    Help,
}

pub fn parse_cmd(s: &str) -> Cmd {
    let s = s.trim();
    let (w, rest) = match s.find(|c: char| c.is_ascii_digit() || c.is_whitespace()) {
        Some(i) => (&s[..i], s[i..].trim()),
        None => (s, ""),
    };
    let n = rest.parse::<usize>().ok();
    if n.is_none() && !rest.is_empty() {
        return Cmd::Help;
    }
    match (w.to_ascii_lowercase().as_str(), n) {
        ("l" | "list", None) => Cmd::List,
        ("v" | "view", Some(n)) => Cmd::View(n),
        ("x" | "exclude", Some(n)) => Cmd::Exclude(n),
        ("i" | "include", Some(n)) => Cmd::Include(n),
        ("e" | "edit", None) => Cmd::Edit,
        ("s" | "send", None) => Cmd::Send,
        ("q" | "quit", None) => Cmd::Quit,
        _ => Cmd::Help,
    }
}

const MENU: &str = "[l]ist files   [v]iew <n>   [x] <n> exclude   [i] <n> include   [e]dit   [s]end   \
[q]uit (keep the folder, send nothing)\n";

/// Only the full word: `y`, `YES` and `yes please` do not send
pub fn is_yes(answer: &str) -> bool {
    answer.trim() == "yes"
}

pub struct ScanCtx<'a> {
    pub red: &'a Redactor,
    pub secrets: Vec<Secret>,
    /// the run's salt, or empty when it is gone (`--send`, `--import`)
    pub salt: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// `q` or end of input: kept, nothing sent
    Kept,
    /// `yes`, but this build has no developer key: nothing written
    NoKey,
    /// `yes`, sealed and written beside the folder
    Sealed(PathBuf),
}

struct Row {
    rel: String,
    size: u64,
    collector: String,
    state: &'static str,
}

pub struct Review<'a> {
    root: PathBuf,
    scan: ScanCtx<'a>,
    head: Vec<String>,
    entries: Vec<Entry>,
    excluded: BTreeSet<String>,
    /// files not in the manifest that the user included with `i`
    added: BTreeSet<String>,
    /// why the send-time scan left a file out
    left_out: BTreeMap<String, String>,
    /// the key `send` encrypts to: [`DEV_KEY`], or a test's own
    key: Option<DevKey>,
}

fn listable(rel: &str) -> bool {
    rel != MANIFEST && rel != PREVIEW_OK && !rel.split('/').any(|c| c.starts_with('.'))
}

fn folder_files(root: &Path) -> Vec<String> {
    let mut v = Vec::new();
    scanner::walk(root, root, &mut v);
    v.retain(|r| listable(r));
    v.sort();
    v
}

impl<'a> Review<'a> {
    pub fn open(root: &Path, scan: ScanCtx<'a>) -> Result<Self, String> {
        let (head, entries) = read_manifest(root)?;
        Ok(Review {
            root: root.to_path_buf(),
            scan,
            head,
            entries,
            excluded: BTreeSet::new(),
            added: BTreeSet::new(),
            left_out: BTreeMap::new(),
            key: DEV_KEY,
        })
    }

    /// Every file in the folder, numbered from 1 in this order
    fn rows(&self) -> Vec<Row> {
        let known: BTreeMap<&str, &Entry> = self.entries.iter().map(|e| (e.rel.as_str(), e)).collect();
        let mut rels: BTreeSet<String> = folder_files(&self.root).into_iter().collect();
        rels.extend(self.entries.iter().map(|e| e.rel.clone()));
        rels.into_iter()
            .map(|rel| {
                let on_disk = fs::symlink_metadata(self.root.join(&rel)).ok();
                let size = on_disk.as_ref().map(|m| m.len()).unwrap_or(0);
                let (collector, state) = match (known.get(rel.as_str()), on_disk.is_some()) {
                    (_, false) => (known.get(rel.as_str()).map(|e| e.collector.clone()).unwrap_or_default(), "deleted"),
                    (Some(e), true) if self.excluded.contains(&rel) => (e.collector.clone(), "excluded"),
                    (Some(e), true) => (e.collector.clone(), "included"),
                    (None, true) if self.added.contains(&rel) => ("user-added".into(), "included"),
                    (None, true) => ("user-added".into(), "new"),
                };
                let state = if self.left_out.contains_key(&rel) { "left out" } else { state };
                Row { rel, size, collector, state }
            })
            .collect()
    }

    fn row(&self, io: &mut Io, n: usize) -> Option<Row> {
        let r = self.rows().into_iter().nth(n.wrapping_sub(1));
        if r.is_none() {
            io.say(&format!("No file {n}; [l]ist shows the numbers.\n"));
        }
        r
    }

    fn list(&self, io: &mut Io) {
        let mut s = String::new();
        for (i, r) in self.rows().iter().enumerate() {
            let mark = match r.state {
                "included" => "   ",
                "excluded" => " x ",
                "new" => "new",
                "left out" => " ! ",
                _ => " - ",
            };
            s.push_str(&format!("{:>3}. [{mark}] {:>9}  {}  — {}", i + 1, util::human(r.size), r.rel, why(&r.collector)));
            match r.state {
                "excluded" => s.push_str(" (excluded: the developer will not see this)"),
                "new" => s.push_str(" (NOT in the manifest: refused unless you include it with i)"),
                "deleted" => s.push_str(" (deleted from the folder)"),
                "left out" => s.push_str(&format!(" (left out by the scan: {})", self.left_out[&r.rel])),
                _ => {}
            }
            s.push('\n');
        }
        io.say(&s);
    }

    fn view(&self, io: &mut Io, rel: &str) {
        let p = self.root.join(rel);
        if io.tty {
            let pager = std::env::var("PAGER").ok().filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "less -R".into());
            let st = std::process::Command::new("sh").arg("-c").arg(format!("{pager} \"$1\"")).arg("sh").arg(&p).status();
            if st.map(|s| s.success()).unwrap_or(false) {
                return;
            }
            io.say(&format!("({pager} did not run; showing the file here)\n"));
        }
        let text = match fs::read(&p) {
            Ok(b) => String::from_utf8_lossy(&b).into_owned(),
            Err(e) => {
                io.say(&format!("{rel}: {}\n", e.kind()));
                return;
            }
        };
        for (i, chunk) in text.lines().collect::<Vec<_>>().chunks(40).enumerate() {
            if i > 0 {
                match io.ask("-- Enter for more, q to stop -- ") {
                    Some(a) if a.trim() == "q" => return,
                    None => return,
                    _ => {}
                }
            }
            let mut s = chunk.join("\n");
            s.push('\n');
            // no terminal control sequences from a file reach the screen
            let s: String = s.chars().map(|c| if c.is_control() && c != '\n' && c != '\t' { '?' } else { c }).collect();
            io.say(&s);
        }
    }

    /// §8.3 step 4 up to the question: re-check against the manifest,
    /// re-scan, and return the files that would be sent
    fn prepare(&mut self, io: &mut Io) -> Vec<Entry> {
        let scanner = Scanner::new(self.scan.red, &self.scan.secrets, &self.scan.salt);
        let on_disk: BTreeSet<String> = folder_files(&self.root).into_iter().collect();
        let mut kept = Vec::new();
        for e in std::mem::take(&mut self.entries) {
            if !on_disk.contains(&e.rel) {
                io.say(&format!("{}: deleted from the folder; it is not sent\n", e.rel));
                continue;
            }
            let p = self.root.join(&e.rel);
            let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            let sha = util::sha256_file(&p).unwrap_or_default();
            if size != e.size || sha != e.sha {
                io.say(&format!("{}: changed since the manifest; scanned again and the manifest updated\n", e.rel));
                kept.push(Entry { size, sha, ..e });
            } else {
                kept.push(e);
            }
        }
        for rel in &on_disk {
            if kept.iter().any(|e| &e.rel == rel) {
                continue;
            }
            let p = self.root.join(rel);
            if self.added.contains(rel) {
                let size = fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                let sha = util::sha256_file(&p).unwrap_or_default();
                kept.push(Entry { rel: rel.clone(), size, sha, collector: "user-added".into() });
            } else {
                io.say(&format!("{rel}: not in the manifest; refused (include it with i to send it)\n"));
            }
        }
        kept.sort_by(|a, b| a.rel.cmp(&b.rel));
        self.left_out.clear();
        for e in &kept {
            if self.excluded.contains(&e.rel) {
                continue;
            }
            let hit = match fs::read(self.root.join(&e.rel)) {
                Ok(d) => scanner.scan_bytes(&e.rel, &d).map(|h| format!("line {}: {}", h.line, h.reason)),
                Err(err) => Some(format!("could not be read for the scan: {}", err.kind())),
            };
            if let Some(why) = hit {
                io.say(&format!("{}: left out by the scan (§6.3), {why}\n", e.rel));
                self.left_out.insert(e.rel.clone(), why);
            }
        }
        self.entries = kept;
        let _ = write_private(&self.root.join(MANIFEST), manifest_text(&self.head, &self.entries, &[]).as_bytes());
        self.entries
            .iter()
            .filter(|e| !self.excluded.contains(&e.rel) && !self.left_out.contains_key(&e.rel))
            .cloned()
            .collect()
    }

    fn save_preview(&self) {
        let p = Preview {
            files: self.entries.iter().map(|e| (e.rel.clone(), e.sha.clone())).collect(),
            excluded: self.excluded.clone(),
        };
        let _ = write_preview(&self.root, &p);
    }

    /// The manifest that travels with the package: the files sent, and a
    /// comment naming each one the user excluded or the scan left out
    fn packed_manifest(&self, send: &[Entry]) -> String {
        let mut extra = Vec::new();
        for rel in &self.excluded {
            extra.push(format!("# excluded by the user at review: {rel}"));
        }
        for (rel, why) in &self.left_out {
            extra.push(format!("# left out by the scan at send: {rel} — {why}"));
        }
        manifest_text(&self.head, send, &extra)
    }

    /// The whole review, until `q`, end of input, or a `yes`
    pub fn run(&mut self, io: &mut Io) -> Outcome {
        match fs::read_to_string(self.root.join(SUMMARY)) {
            Ok(s) => io.say(&s),
            Err(e) => io.say(&format!("({SUMMARY} could not be read: {})\n", e.kind())),
        }
        io.say(&format!("\n{BY_HAND}\n"));
        match read_preview(&self.root) {
            Ok(Some(p)) => {
                self.excluded = p.excluded.iter().filter(|r| self.entries.iter().any(|e| &e.rel == *r)).cloned().collect();
                let now: BTreeMap<String, String> = folder_files(&self.root)
                    .into_iter()
                    .map(|r| {
                        let h = util::sha256_file(&self.root.join(&r)).unwrap_or_default();
                        (r, h)
                    })
                    .collect();
                let changed: Vec<&String> = now.keys().chain(p.files.keys()).filter(|r| now.get(*r) != p.files.get(*r)).collect();
                let changed: BTreeSet<&String> = changed.into_iter().collect();
                if changed.is_empty() {
                    io.say("No file changed since your last review.\n");
                } else {
                    io.say("Changed since your last review (each is scanned again at send):\n");
                    for r in changed {
                        io.say(&format!("  {r}\n"));
                    }
                }
                if !self.excluded.is_empty() {
                    io.say(&format!("Still excluded from your last review: {}\n", self.excluded.iter().cloned().collect::<Vec<_>>().join(", ")));
                }
            }
            Ok(None) => {}
            Err(e) => io.say(&format!("{e}; your earlier exclusions are not used, check the list again\n")),
        }
        if self.key.is_none() {
            io.say(
                "\nThis build of irondivi-cli carries no developer key, so [s]end checks the folder \
                 and asks, then stops before anything is packed or written (§8.4).\n",
            );
        }
        io.say(&format!("\nThe folder is {}\n", self.root.display()));
        loop {
            let Some(line) = io.ask(&format!("\n{MENU}> ")) else {
                self.save_preview();
                return Outcome::Kept;
            };
            if line.trim().is_empty() {
                continue;
            }
            match parse_cmd(&line) {
                Cmd::List => self.list(io),
                Cmd::View(n) => {
                    if let Some(r) = self.row(io, n) {
                        self.view(io, &r.rel);
                    }
                }
                Cmd::Exclude(n) => {
                    if let Some(r) = self.row(io, n) {
                        if r.state == "new" || r.state == "deleted" {
                            self.added.remove(&r.rel);
                            io.say(&format!("{}: not sent\n", r.rel));
                        } else {
                            self.excluded.insert(r.rel.clone());
                            io.say(&format!("{}: excluded. The developer will not see {}.\n", r.rel, why(&r.collector)));
                        }
                    }
                }
                Cmd::Include(n) => {
                    if let Some(r) = self.row(io, n) {
                        if r.state == "new" {
                            self.added.insert(r.rel.clone());
                            io.say(&format!("{}: included; it is scanned at send\n", r.rel));
                        } else if r.state == "deleted" {
                            io.say(&format!("{}: it is no longer in the folder\n", r.rel));
                        } else {
                            self.excluded.remove(&r.rel);
                            io.say(&format!("{}: included\n", r.rel));
                        }
                    }
                }
                Cmd::Edit => {
                    io.say(&format!(
                        "Open {} in your own editor or file manager and change or delete any file. \
                         Changed files are scanned again at send; new files are refused unless you \
                         include them with i.\n",
                        self.root.display()
                    ));
                    let _ = io.ask("Press Enter when you are done. ");
                }
                Cmd::Help => io.say("One of: l, v <n>, x <n>, i <n>, e, s, q.\n"),
                Cmd::Quit => {
                    self.save_preview();
                    return Outcome::Kept;
                }
                Cmd::Send => {
                    let send = self.prepare(io);
                    self.save_preview();
                    if send.is_empty() {
                        io.say("No file is left to send.\n");
                        continue;
                    }
                    // the manifest travels, so it is counted
                    let man = self.packed_manifest(&send);
                    let total: u64 = send.iter().map(|e| e.size).sum::<u64>() + man.len() as u64;
                    io.say("\nThese files would be sent:\n");
                    for e in &send {
                        io.say(&format!("  {:>9}  {}\n", util::human(e.size), e.rel));
                    }
                    io.say(&format!("  {:>9}  {MANIFEST}\n", util::human(man.len() as u64)));
                    let q = format!(
                        "Send these {} files ({}) to the IronDivi developer? [yes/no] ",
                        send.len() + 1,
                        util::human(total)
                    );
                    let Some(a) = io.ask(&q) else {
                        return Outcome::Kept;
                    };
                    if !is_yes(&a) {
                        io.say("Not sent: only the full word yes sends.\n");
                        continue;
                    }
                    let Some(key) = self.key else {
                        io.say(
                            "No developer key is compiled into this build of irondivi-cli, so nothing \
                             is send-ready: nothing was packed, written or sent. The folder is kept.\n",
                        );
                        return Outcome::NoKey;
                    };
                    let tar = match pack(&self.root, &send, &man) {
                        Ok(t) => t,
                        Err(e) => {
                            io.say(&format!("Packing failed: {e}. Nothing was written or sent.\n"));
                            return Outcome::Kept;
                        }
                    };
                    match seal(key.recipient, &tar) {
                        Ok(ct) => {
                            let name = format!("{}.age", self.root.file_name().and_then(|n| n.to_str()).unwrap_or("irondivi-diag"));
                            let path = self.root.with_file_name(name);
                            if let Err(e) = write_private(&path, &ct) {
                                io.say(&format!("Writing {} failed: {}. Nothing was sent.\n", path.display(), e.kind()));
                                return Outcome::Kept;
                            }
                            io.say(&format!(
                                "Encrypted to the developer's key {} and written to {}\n(SHA-256 {}). It is safe to send \
                                 by e-mail or chat: only the developer's private key can open it.\n",
                                key.fingerprint,
                                path.display(),
                                hex::encode(Sha256::digest(&ct))
                            ));
                            return Outcome::Sealed(path);
                        }
                        Err(e) => {
                            io.say(&format!("Encryption failed: {e}. Nothing was written or sent.\n"));
                            return Outcome::Kept;
                        }
                    }
                }
            }
        }
    }
}

/// The files to send and their manifest as one tar, in memory. Names,
/// owners and times say nothing about who packed it.
pub fn pack(root: &Path, send: &[Entry], manifest: &str) -> Result<Vec<u8>, String> {
    let mut w = crate::tar::Writer::new(Vec::new());
    for e in send {
        let d = fs::read(root.join(&e.rel)).map_err(|err| format!("{}: {}", e.rel, err.kind()))?;
        if hex::encode(Sha256::digest(&d)) != e.sha {
            return Err(format!("{} changed while it was being packed", e.rel));
        }
        w.file(&e.rel, &d, 0).map_err(|err| format!("{}: {err}", e.rel))?;
    }
    w.file(MANIFEST, manifest.as_bytes(), 0).map_err(|err| err.to_string())?;
    w.finish().map_err(|e| e.to_string())
}

/// §8.4: zstd, then `age` (binary format, X25519) to `recipient`. Only
/// the holder of the matching identity can open it; a changed byte makes
/// it fail to open rather than open to something else.
pub fn seal(recipient: &str, tar: &[u8]) -> Result<Vec<u8>, String> {
    let r: age::x25519::Recipient = recipient.parse().map_err(|e| format!("the developer key does not parse: {e}"))?;
    let z = zstd::bulk::compress(tar, ZSTD_LEVEL).map_err(|e| format!("compressing: {}", e.kind()))?;
    let enc = age::Encryptor::with_recipients(std::iter::once(&r as &dyn age::Recipient)).map_err(|e| format!("encrypting: {e}"))?;
    let mut out = Vec::with_capacity(z.len() + 512);
    let mut w = enc.wrap_output(&mut out).map_err(|e| format!("encrypting: {}", e.kind()))?;
    w.write_all(&z).map_err(|e| format!("encrypting: {}", e.kind()))?;
    w.finish().map_err(|e| format!("encrypting: {}", e.kind()))?;
    Ok(out)
}

// ----------------------------------------------------------- entry points

fn send_cmd(root: &Path) -> String {
    format!("irondivi-cli diag --send {}", root.display())
}

/// The secrets §6.3 searches for: the configs and cookies discovery finds now
pub fn current_secrets(o: &Options) -> Vec<Secret> {
    let mirrors = discovery::mirror_roots();
    let (live, stale, unreadable) = discovery::path_records(&mirrors);
    let nodes = discovery::find_nodes(&live);
    let found = discovery::discover(o.datadir.as_deref(), o.conf.as_deref(), &nodes, stale, unreadable);
    let confs: Vec<PathBuf> = found.dirs.iter().filter_map(|d| d.conf.clone()).collect();
    let cookies: Vec<PathBuf> = found.dirs.iter().flat_map(|d| [d.path.join(".cookie"), d.chain.join(".cookie")]).collect();
    scanner::secrets_of(&confs, &cookies)
}

/// After a run or an import: the review on a terminal, else how to send later
pub fn after_collect(root: &Path, o: &Options, scan: ScanCtx) -> Outcome {
    if o.submit == Some(false) {
        eprintln!("irondivi-cli diag: --no-submit: nothing is sent. To review and send it later: {}", send_cmd(root));
        return Outcome::Kept;
    }
    if !util::is_tty() {
        eprintln!("irondivi-cli diag: no terminal, so nothing is sent (R2). To review and send it later: {}", send_cmd(root));
        return Outcome::Kept;
    }
    review_on_terminal(root, scan)
}

fn review_on_terminal(root: &Path, scan: ScanCtx) -> Outcome {
    let mut rv = match Review::open(root, scan) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("irondivi-cli diag: cannot review {}: {e}", root.display());
            return Outcome::Kept;
        }
    };
    let stdin = io::stdin();
    let mut inp = stdin.lock();
    let mut out = io::stdout();
    let mut t = Io { inp: &mut inp, out: &mut out, tty: true };
    let r = rv.run(&mut t);
    if r == Outcome::Kept {
        println!("Nothing was sent. The folder stays at {}\nTo send it later: {}", root.display(), send_cmd(root));
    }
    r
}

/// `irondivi-cli diag --send <folder>`: §8.3 step 4 again on a saved folder
pub fn send_main(folder: &Path, o: &Options) -> i32 {
    unsafe { libc::umask(0o077) };
    let root = match fs::canonicalize(folder) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("irondivi-cli diag: --send {}: {}", folder.display(), util::io_err(&e));
            return 1;
        }
    };
    if !root.join(MANIFEST).is_file() || !root.join(SUMMARY).is_file() {
        eprintln!("irondivi-cli diag: --send: {} is not a diag folder (no {SUMMARY} or {MANIFEST})", root.display());
        return 1;
    }
    if !util::is_tty() {
        eprintln!("irondivi-cli diag: --send needs a terminal: nothing is ever sent without one (R2)");
        return 1;
    }
    let red = Redactor::new(Redactor::new_salt(), &discovery::known_values());
    let scan = ScanCtx { red: &red, secrets: current_secrets(o), salt: Vec::new() };
    match review_on_terminal(&root, scan) {
        Outcome::Sealed(_) => 0,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Known;

    fn red() -> Redactor {
        Redactor::new(
            [9u8; 32],
            &Known { hostnames: vec!["canaryhostrr".into()], users: vec!["canaryuserrr".into()], ..Default::default() },
        )
    }

    fn io_run(input: &str, f: impl FnOnce(&mut Io) -> Outcome) -> (Outcome, String) {
        let mut inp = io::Cursor::new(input.as_bytes().to_vec());
        let mut out = Vec::new();
        let r = {
            let mut t = Io { inp: &mut inp, out: &mut out, tty: false };
            f(&mut t)
        };
        (r, String::from_utf8(out).unwrap())
    }

    /// a folder with a summary, two files and their manifest
    fn folder(d: &Path) {
        fs::write(d.join(SUMMARY), "SUMMARY canary-free\n").unwrap();
        fs::create_dir_all(d.join("host")).unwrap();
        fs::write(d.join("host/host.txt"), "uptime 3 days\n").unwrap();
        fs::write(d.join(REPORT), "The user's own report\n").unwrap();
        let mut m = String::from("# path\tsize\tsha256\tcollector\n");
        for (rel, who) in [(SUMMARY, "diag"), ("host/host.txt", "host"), (REPORT, "user")] {
            let p = d.join(rel);
            m.push_str(&format!("{rel}\t{}\t{}\t{who}\n", fs::metadata(&p).unwrap().len(), util::sha256_file(&p).unwrap()));
        }
        fs::write(d.join(MANIFEST), m).unwrap();
    }

    #[test]
    fn only_the_full_word_yes() {
        assert!(is_yes("yes"));
        assert!(is_yes("  yes \n"));
        for a in ["y", "YES", "Yes", "yes please", "", "no", "ye s"] {
            assert!(!is_yes(a), "{a:?}");
        }
    }

    #[test]
    fn menu_parses() {
        assert_eq!(parse_cmd("l"), Cmd::List);
        assert_eq!(parse_cmd("v 3"), Cmd::View(3));
        assert_eq!(parse_cmd("v3"), Cmd::View(3));
        assert_eq!(parse_cmd("x 12"), Cmd::Exclude(12));
        assert_eq!(parse_cmd("i 1"), Cmd::Include(1));
        assert_eq!(parse_cmd("e"), Cmd::Edit);
        assert_eq!(parse_cmd("S"), Cmd::Send);
        assert_eq!(parse_cmd("q"), Cmd::Quit);
        assert_eq!(parse_cmd("x"), Cmd::Help);
        assert_eq!(parse_cmd("send everything"), Cmd::Help);
    }

    #[test]
    fn report_file_sections_and_canaries() {
        let a = parse_report_file("crashed at start\n## 2\nOct 30 around 10:00 after upgrade\n## 5\nhost canaryhostrr user canaryuserrr addr DCanaryAddrRr123456789abcdefghijkm\n");
        assert_eq!(a[0], "crashed at start");
        assert_eq!(a[1], "Oct 30 around 10:00 after upgrade");
        assert_eq!(a[2], "");
        let t = render_report(&a, "Answers read from --report-file.", &red());
        for c in ["canaryhostrr", "canaryuserrr", "DCanaryAddrRr123456789abcdefghijkm"] {
            assert!(!t.contains(c), "{c} survived:\n{t}");
        }
        assert!(t.contains("3. What changed before it started?"));
        assert!(t.contains("(no answer)"));
        assert_eq!(reported_start(&t).as_deref(), Some("Oct 30 around 10:00 after upgrade"));
    }

    #[test]
    fn asked_report_ends_at_an_empty_line() {
        let mut inp = io::Cursor::new(b"line one\nline two\n\nyesterday\n\nls\n".to_vec());
        let mut out = Vec::new();
        let a = ask_report(&mut Io { inp: &mut inp, out: &mut out, tty: false });
        assert_eq!(a[0], "line one\nline two");
        assert_eq!(a[1], "yesterday");
        assert_eq!(a[2], "");
        assert_eq!(a[3], "ls");
        assert_eq!(a[4], "");
    }

    #[test]
    fn preview_round_trip_and_tamper() {
        let d = tempfile::tempdir().unwrap();
        let mut p = Preview::default();
        p.files.insert("a.txt".into(), "00".repeat(32));
        p.excluded.insert("a.txt".into());
        write_preview(d.path(), &p).unwrap();
        assert_eq!(read_preview(d.path()).unwrap(), Some(p));
        let s = fs::read_to_string(d.path().join(PREVIEW_OK)).unwrap().replace(&"00".repeat(32), &"11".repeat(32));
        fs::write(d.path().join(PREVIEW_OK), s).unwrap();
        assert!(read_preview(d.path()).is_err());
        fs::remove_file(d.path().join(PREVIEW_OK)).unwrap();
        assert_eq!(read_preview(d.path()).unwrap(), None);
    }

    #[test]
    fn review_never_sends_without_yes_and_stops_at_no_key() {
        let d = tempfile::tempdir().unwrap();
        folder(d.path());
        let r = red();
        let name = d.path().file_name().unwrap().to_string_lossy().into_owned();
        let beside = || -> Vec<String> {
            fs::read_dir(d.path().parent().unwrap())
                .unwrap()
                .filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .filter(|n| n.starts_with(&name))
                .collect()
        };
        let before = beside();
        let inside = folder_files(d.path());
        let (o, out) = io_run("l\nx 2\ns\ny\ns\nYES\ns\nyes\n", |io| {
            let mut rv = Review::open(d.path(), ScanCtx { red: &r, secrets: vec![], salt: vec![] }).unwrap();
            rv.key = None; // a build with no developer key
            rv.run(io)
        });
        assert_eq!(o, Outcome::NoKey, "{out}");
        assert_eq!(out.matches("Not sent: only the full word yes sends.").count(), 2, "{out}");
        assert!(out.contains("01-user-report.txt: excluded"), "{out}");
        assert!(out.contains("Send these 3 files"), "{out}");
        assert!(out.contains("nothing was packed, written or sent"), "{out}");
        // nothing new beside the folder; the exclusion is remembered
        assert_eq!(before, beside());
        assert_eq!(inside, folder_files(d.path()));
        let p = read_preview(d.path()).unwrap().unwrap();
        assert!(p.excluded.contains(REPORT));
    }

    #[test]
    fn send_rescans_changed_and_refuses_new_files() {
        let d = tempfile::tempdir().unwrap();
        folder(d.path());
        let r = red();
        // edited after the manifest: a host name typed back in
        fs::write(d.path().join("host/host.txt"), "uptime 3 days on canaryhostrr\n").unwrap();
        fs::write(d.path().join("notes.txt"), "my own notes\n").unwrap();
        let (_, out) = io_run("s\nno\nq\n", |io| {
            Review::open(d.path(), ScanCtx { red: &r, secrets: vec![], salt: vec![] }).unwrap().run(io)
        });
        assert!(out.contains("host/host.txt: changed since the manifest"), "{out}");
        assert!(out.contains("host/host.txt: left out by the scan"), "{out}");
        assert!(out.contains("notes.txt: not in the manifest; refused"), "{out}");
        assert!(out.contains("Send these 3 files"), "{out}");
        // included with i, the new file is scanned and goes in
        let (_, out) = io_run("l\ni 4\ns\nno\nq\n", |io| {
            Review::open(d.path(), ScanCtx { red: &r, secrets: vec![], salt: vec![] }).unwrap().run(io)
        });
        assert!(out.contains("Changed since your last review"), "{out}");
        assert!(out.contains("notes.txt: included"), "{out}");
        assert!(out.contains("Send these 4 files"), "{out}");
        let (_, m) = read_manifest(d.path()).unwrap();
        assert!(m.iter().any(|e| e.rel == "notes.txt" && e.collector == "user-added"));
    }

    #[test]
    fn pack_carries_only_the_chosen_files() {
        let d = tempfile::tempdir().unwrap();
        folder(d.path());
        let (_, m) = read_manifest(d.path()).unwrap();
        let send: Vec<Entry> = m.into_iter().filter(|e| e.rel != REPORT).collect();
        let t = pack(d.path(), &send, "# m\n").unwrap();
        let names: Vec<String> = crate::tar::read_all(&mut t.as_slice(), 1 << 20, 1 << 20)
            .unwrap()
            .into_iter()
            .map(|m| match m {
                crate::tar::Member::File { name, .. } => name,
                crate::tar::Member::Skipped { name, .. } => panic!("{name}"),
            })
            .collect();
        assert_eq!(names, vec![SUMMARY.to_string(), "host/host.txt".into(), MANIFEST.into()]);
    }

    // ------------------------------------------------------------ §8.4 seal

    fn open_sealed(id: &age::x25519::Identity, ct: &[u8]) -> Result<Vec<u8>, String> {
        let dec = age::Decryptor::new_buffered(ct).map_err(|e| e.to_string())?;
        let mut r = dec.decrypt(std::iter::once(id as &dyn age::Identity)).map_err(|e| e.to_string())?;
        let mut z = Vec::new();
        io::Read::read_to_end(&mut r, &mut z).map_err(|e| e.to_string())?;
        zstd::stream::decode_all(&z[..]).map_err(|e| e.to_string())
    }

    fn members(tar: &[u8]) -> BTreeMap<String, Vec<u8>> {
        crate::tar::read_all(&mut &tar[..], u64::MAX, u64::MAX)
            .unwrap()
            .into_iter()
            .map(|m| match m {
                crate::tar::Member::File { name, data } => (name, data),
                _ => panic!("unexpected tar member"),
            })
            .collect()
    }

    #[test]
    fn dev_key_parses_as_an_age_recipient() {
        let k = DEV_KEY.expect("a developer key is compiled in");
        let _: age::x25519::Recipient = k.recipient.parse().expect("DEV_KEY is an age X25519 recipient");
        assert_eq!(k.fingerprint, &hex::encode(Sha256::digest(k.recipient.as_bytes()))[..16]);
        // and seal() accepts it
        assert!(seal(k.recipient, b"x").unwrap().starts_with(b"age-encryption.org/v1\n"));
    }

    #[test]
    fn seal_round_trips_byte_identical_and_tamper_fails() {
        let d = tempfile::tempdir().unwrap();
        folder(d.path());
        // a binary file that does not compress, and an empty one
        let noise: Vec<u8> = (0..70_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        fs::write(d.path().join("host/noise.bin"), &noise).unwrap();
        fs::write(d.path().join("host/empty.txt"), b"").unwrap();
        let mut send = read_manifest(d.path()).unwrap().1;
        for rel in ["host/noise.bin", "host/empty.txt"] {
            let p = d.path().join(rel);
            send.push(Entry { rel: rel.into(), size: fs::metadata(&p).unwrap().len(), sha: util::sha256_file(&p).unwrap(), collector: "t".into() });
        }
        let man = fs::read_to_string(d.path().join(MANIFEST)).unwrap();
        let tar = pack(d.path(), &send, &man).unwrap();

        let id = age::x25519::Identity::generate();
        let ct = seal(&id.to_public().to_string(), &tar).unwrap();
        assert!(!ct.windows(14).any(|w| w == b"uptime 3 days\n"), "plaintext leaked into the package");
        let back = open_sealed(&id, &ct).unwrap();
        assert_eq!(back, tar);
        let got = members(&back);
        assert_eq!(got.len(), send.len() + 1);
        for e in &send {
            assert_eq!(got[&e.rel], fs::read(d.path().join(&e.rel)).unwrap(), "{}", e.rel);
        }
        assert_eq!(got[MANIFEST], man.as_bytes());

        // another identity cannot open it
        assert!(open_sealed(&age::x25519::Identity::generate(), &ct).is_err());
        // a changed byte in the header, in the body, or a cut tail fails to open
        for at in [30, ct.len() / 2, ct.len() - 1] {
            let mut bad = ct.clone();
            bad[at] ^= 0x01;
            assert!(open_sealed(&id, &bad).is_err(), "flipped byte {at} still opened");
        }
        assert!(open_sealed(&id, &ct[..ct.len() - 20]).is_err());
        // a bad recipient is refused, never sent in clear
        assert!(seal("age1notakey", &tar).is_err());
    }

    #[test]
    fn review_yes_seals_beside_the_folder() {
        let d = tempfile::tempdir().unwrap();
        folder(d.path());
        let r = red();
        let id = age::x25519::Identity::generate();
        let pk: &'static str = Box::leak(id.to_public().to_string().into_boxed_str());
        let (o, out) = io_run("x 2\ns\nyes\n", |io| {
            let mut rv = Review::open(d.path(), ScanCtx { red: &r, secrets: vec![], salt: vec![] }).unwrap();
            rv.key = Some(DevKey { recipient: pk, fingerprint: "testfingerprint0" });
            rv.run(io)
        });
        let Outcome::Sealed(path) = o else { panic!("not sealed: {out}") };
        assert_eq!(path.parent(), d.path().parent());
        assert!(out.contains("testfingerprint0"), "{out}");
        let ct = fs::read(&path).unwrap();
        let _ = fs::remove_file(&path);
        let got = members(&open_sealed(&id, &ct).unwrap());
        // the excluded report is not in it; the manifest notes it
        assert!(!got.contains_key(REPORT));
        assert_eq!(got["host/host.txt"], b"uptime 3 days\n");
        assert_eq!(got[SUMMARY], fs::read(d.path().join(SUMMARY)).unwrap());
        assert!(String::from_utf8_lossy(&got[MANIFEST]).contains(REPORT), "the manifest names the excluded file");
    }
}
