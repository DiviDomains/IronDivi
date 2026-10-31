// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! §6.3 "The final scanner": the last check over the finished folder.
//!
//! It never trusts the collectors' own scrub. For every file it asks three
//! questions, and a file that fails any of them is left out:
//!
//! 1. Would the redaction pass still change it? (`scrub(text) != text`)
//! 2. Does any known value, secret or the run's salt appear in it, in any
//!    of the encodings §6.3 lists? The needle is encoded; the file is never
//!    decoded.
//! 3. Is a staker, per-block or counted-list line still standing?
//!
//! A hit names the file, the line number and what was found, never the
//! value itself. [`verify_sha`] re-checks the folder against its manifest
//! at preview and again at submit.

use crate::oldlog;
use crate::redact::Redactor;
use regex::bytes::Regex;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// One reason a file is left out
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    /// path relative to the package root
    pub file: String,
    /// 1-based line number
    pub line: usize,
    /// what was found, safe to show: never the value
    pub reason: String,
}

/// A value that must not appear, with a label safe to show
#[derive(Clone, Debug)]
pub struct Secret {
    pub value: String,
    pub label: String,
}

#[derive(Clone)]
struct Needle {
    label: String,
    /// a whole word only (known values, short secrets); else any substring
    word: bool,
}

pub struct Scanner<'a> {
    red: &'a Redactor,
    re: Option<Regex>,
    needles: HashMap<Vec<u8>, Needle>,
}

/// Files the scanner does not read: the manifest is a list of hashes
/// written after the scan, and dotfiles are diag's own temporaries
fn skipped(rel: &str) -> bool {
    rel == "02-manifest.txt" || rel.split('/').any(|c| c.starts_with('.'))
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding
pub fn base64(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for ch in data.chunks(3) {
        let b = [ch[0], *ch.get(1).unwrap_or(&0), *ch.get(2).unwrap_or(&0)];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        for i in 0..4 {
            if i <= ch.len() {
                out.push(B64[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The part of `v`'s base64 that does not depend on the bytes around it,
/// for `v` starting at offset 0, 1 and 2 of a 3-byte group
fn base64_alignments(v: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    for k in 0..3usize {
        let mut buf = vec![0u8; k];
        buf.extend_from_slice(v);
        let enc = base64(&buf);
        let start = if k == 0 { 0 } else { 4 };
        let end = (buf.len() / 3) * 4;
        if end > start && end - start >= 6 {
            out.push(enc[start..end].to_string());
        }
    }
    out
}

fn url_encode(v: &str) -> String {
    let mut s = String::new();
    for b in v.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            s.push(b as char);
        } else {
            s.push_str(&format!("%{b:02X}"));
        }
    }
    s
}

fn utf16le(v: &str) -> Vec<u8> {
    v.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// The reversed byte order of a hex string (hashes printed both ways)
fn reversed_hex(v: &str) -> Option<String> {
    if v.len() < 16 || v.len() % 2 != 0 {
        return None;
    }
    let mut b = hex::decode(v).ok()?;
    b.reverse();
    Some(hex::encode(b))
}

impl<'a> Scanner<'a> {
    /// `salt` is the run's raw salt; `secrets` are values read from the
    /// configs and cookies (kept in memory only)
    pub fn new(red: &'a Redactor, secrets: &[Secret], salt: &[u8]) -> Self {
        let mut needles: HashMap<Vec<u8>, Needle> = HashMap::new();
        let mut add = |n: Vec<u8>, label: String, word: bool| {
            if n.len() >= 3 {
                needles.entry(n).or_insert(Needle { label, word });
            }
        };
        let encoded = |add: &mut dyn FnMut(Vec<u8>, String, bool), v: &str, what: &str| {
            if v.len() < 6 {
                return;
            }
            add(hex::encode(v).into_bytes(), format!("{what} (hex)"), false);
            add(hex::encode_upper(v).into_bytes(), format!("{what} (hex)"), false);
            for b in base64_alignments(v.as_bytes()) {
                add(b.into_bytes(), format!("{what} (base64)"), false);
            }
            let u = url_encode(v);
            if u != v {
                add(u.into_bytes(), format!("{what} (URL-encoded)"), false);
            }
            let j = serde_json::to_string(v).unwrap_or_default();
            let j = j.trim_matches('"');
            if j != v {
                add(j.as_bytes().to_vec(), format!("{what} (JSON-escaped)"), false);
            }
            // JSON writers that escape the solidus too
            if j.contains('/') {
                add(j.replace('/', "\\/").into_bytes(), format!("{what} (JSON-escaped)"), false);
            }
            add(utf16le(v), format!("{what} (UTF-16LE)"), false);
            if let Some(r) = reversed_hex(v) {
                add(r.into_bytes(), format!("{what} (reversed bytes)"), false);
            }
        };

        for (v, kind) in red.known_values() {
            let what = match kind {
                "host" => "a known host name",
                "u" => "a known user name",
                "mid" => "a machine id",
                _ => "a known value",
            };
            add(v.as_bytes().to_vec(), what.to_string(), true);
            add(v.to_ascii_lowercase().into_bytes(), format!("{what} (lower case)"), true);
            add(v.to_ascii_uppercase().into_bytes(), format!("{what} (upper case)"), true);
            encoded(&mut add, v, what);
        }
        for s in secrets {
            let v = s.value.trim();
            if v.len() < 4 || v.starts_with('<') {
                continue;
            }
            // a short secret is a whole word only, or it matches inside words
            add(v.as_bytes().to_vec(), s.label.clone(), v.len() < 8);
            encoded(&mut add, v, &s.label);
        }
        if !salt.is_empty() {
            let what = "the run's salt";
            add(salt.to_vec(), format!("{what} (raw bytes)"), false);
            let h = hex::encode(salt);
            add(h.clone().into_bytes(), format!("{what} (hex)"), false);
            add(h.to_ascii_uppercase().into_bytes(), format!("{what} (hex)"), false);
            if let Some(r) = reversed_hex(&h) {
                add(r.into_bytes(), format!("{what} (reversed bytes)"), false);
            }
            for b in base64_alignments(salt) {
                add(b.into_bytes(), format!("{what} (base64)"), false);
            }
            encoded(&mut add, &h, &format!("{what} as text"));
        }

        let mut keys: Vec<&Vec<u8>> = needles.keys().collect();
        keys.sort_by(|a, b| b.len().cmp(&a.len()).then(a.cmp(b)));
        let re = if keys.is_empty() {
            None
        } else {
            let alts: Vec<String> = keys
                .iter()
                .map(|k| k.iter().map(|b| format!("\\x{b:02x}")).collect::<String>())
                .collect();
            Regex::new(&format!("(?-u)(?:{})", alts.join("|"))).ok()
        };
        Scanner { red, re, needles }
    }

    /// The first hit in one file's bytes, if any
    pub fn scan_bytes(&self, rel: &str, data: &[u8]) -> Option<Hit> {
        let line_of = |off: usize| data[..off].iter().filter(|b| **b == b'\n').count() + 1;
        let hit = |line: usize, reason: String| Some(Hit { file: rel.to_string(), line, reason });

        // 2: needles, in raw bytes
        if let Some(re) = &self.re {
            let mut at = 0;
            while let Some(m) = re.find_at(data, at) {
                let n = &self.needles[m.as_bytes()];
                let before = m.start().checked_sub(1).map(|i| data[i]);
                let after = data.get(m.end()).copied();
                let left_ok = before.is_none_or(|b| !(b.is_ascii_alphanumeric() || b"_.-".contains(&b)));
                let right_ok = after.is_none_or(|b| !(b.is_ascii_alphanumeric() || b"_-".contains(&b)));
                if !n.word || (left_ok && right_ok) {
                    return hit(line_of(m.start()), format!("{} is still in the file", n.label));
                }
                at = m.start() + 1;
            }
        }

        let text = String::from_utf8_lossy(data);
        // 3: line classes the old-log filter removes
        for (i, l) in text.lines().enumerate() {
            if let Some(what) = oldlog::would_remove(l) {
                return hit(i + 1, format!("a line the §6.2 old-log filter removes is still standing ({what})"));
            }
        }
        // 1: the redaction pass would still change it
        let scrubbed = self.red.scrub(&text);
        if scrubbed != text {
            let (a, b): (Vec<&str>, Vec<&str>) = (text.split('\n').collect(), scrubbed.split('\n').collect());
            let i = a.iter().zip(b.iter()).position(|(x, y)| x != y).unwrap_or(a.len().min(b.len()));
            let token = b
                .get(i)
                .and_then(|l| {
                    let orig: Vec<&str> = a.get(i).map(|o| o.split_whitespace().collect()).unwrap_or_default();
                    l.split_whitespace().find(|w| !orig.contains(w)).map(str::to_string)
                })
                .unwrap_or_else(|| "a removed block".into());
            // the replacement token is the scrub's own output, safe to show
            let token: String = token.chars().take(60).collect();
            return hit(i + 1, format!("the redaction pass would still change this line (to {token})"));
        }
        None
    }

    /// Scan every file in the package; one hit per file at most
    pub fn scan_folder(&self, root: &Path) -> Vec<Hit> {
        let mut files = Vec::new();
        walk(root, root, &mut files);
        files.sort();
        let mut hits = Vec::new();
        for rel in files {
            if skipped(&rel) {
                continue;
            }
            match fs::read(root.join(&rel)) {
                Ok(data) => {
                    if let Some(h) = self.scan_bytes(&rel, &data) {
                        hits.push(h);
                    }
                }
                Err(e) => hits.push(Hit { file: rel, line: 0, reason: format!("could not be read for the scan: {}", e.kind()) }),
            }
        }
        hits
    }
}

/// Regular files only; a symlink is listed as a file and never followed
pub fn walk(root: &Path, dir: &Path, out: &mut Vec<String>) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            let p = e.path();
            let ft = match e.file_type() {
                Ok(t) => t,
                Err(_) => continue,
            };
            if ft.is_dir() {
                walk(root, &p, out);
            } else if let Ok(rel) = p.strip_prefix(root) {
                out.push(rel.to_string_lossy().into_owned());
            }
        }
    }
}

/// Values from each data dir's config and cookie that must not appear:
/// `rpcpassword`, `rpcuser` and the cookie. Held in memory only.
pub fn secrets_of(confs: &[std::path::PathBuf], cookies: &[std::path::PathBuf]) -> Vec<Secret> {
    let mut out = Vec::new();
    let mut user = None;
    let mut pass = None;
    for c in confs {
        let Some(t) = crate::util::read_small(c, 1 << 20) else { continue };
        for l in t.lines() {
            let l = l.trim();
            if l.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = l.split_once('=') {
                let (k, v) = (k.trim(), v.trim().trim_matches('"'));
                match k {
                    "rpcpassword" => {
                        out.push(Secret { value: v.into(), label: "the rpcpassword".into() });
                        pass = Some(v.to_string());
                    }
                    "rpcuser" if !matches!(v, "divi" | "irondivi" | "user" | "admin" | "root") => {
                        out.push(Secret { value: v.into(), label: "the rpcuser".into() });
                        user = Some(v.to_string());
                    }
                    "rpcuser" => user = Some(v.to_string()),
                    _ => {}
                }
            }
        }
        if let (Some(u), Some(p)) = (&user, &pass) {
            out.push(Secret { value: base64(format!("{u}:{p}").as_bytes()), label: "base64 of rpcuser:rpcpassword".into() });
        }
    }
    for c in cookies {
        let Some(t) = crate::util::read_small(c, 4096) else { continue };
        let t = t.trim();
        out.push(Secret { value: base64(t.as_bytes()), label: "base64 of the RPC cookie".into() });
        if let Some((_, v)) = t.split_once(':') {
            out.push(Secret { value: v.into(), label: "the RPC cookie".into() });
        } else {
            out.push(Secret { value: t.into(), label: "the RPC cookie".into() });
        }
    }
    out
}

/// §6.3: the folder against its manifest, before preview and at submit.
/// Returns the files whose size or SHA-256 differ, and files the manifest
/// does not list (other than the manifest itself).
pub fn verify_sha(root: &Path) -> Result<Vec<String>, String> {
    let m = fs::read_to_string(root.join("02-manifest.txt")).map_err(|e| format!("02-manifest.txt: {}", e.kind()))?;
    let mut listed = std::collections::HashSet::new();
    let mut bad = Vec::new();
    for l in m.lines() {
        if l.starts_with('#') || l.trim().is_empty() {
            continue;
        }
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 3 {
            continue;
        }
        listed.insert(f[0].to_string());
        let p = root.join(f[0]);
        let ok = fs::symlink_metadata(&p).map(|md| md.is_file() && md.len().to_string() == f[1]).unwrap_or(false)
            && crate::util::sha256_file(&p).map(|h| h == f[2]).unwrap_or(false);
        if !ok {
            bad.push(format!("{}: changed or missing since the manifest", f[0]));
        }
    }
    let mut files = Vec::new();
    walk(root, root, &mut files);
    for f in files {
        if !skipped(&f) && !listed.contains(&f) {
            bad.push(format!("{f}: not in the manifest"));
        }
    }
    Ok(bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Known;

    fn known() -> Known {
        Known {
            hostnames: vec!["canaryhost7".into(), "hp3".into()],
            users: vec!["carolcanary".into()],
            machine_ids: vec!["0123456789abcdef0123456789abcdef".into()],
            ips: vec![],
        }
    }

    fn setup() -> (Redactor, [u8; 32]) {
        let salt = [7u8; 32];
        (Redactor::new(salt, &known()), salt)
    }

    fn secrets() -> Vec<Secret> {
        vec![
            Secret { value: "Sup3rS3cretPw".into(), label: "the rpcpassword".into() },
            Secret { value: "c00kiec00kiec00kie".into(), label: "the RPC cookie".into() },
        ]
    }

    fn hit(text: &str) -> Option<Hit> {
        let (r, salt) = setup();
        let s = Scanner::new(&r, &secrets(), &salt);
        s.scan_bytes("f.txt", text.as_bytes())
    }

    #[test]
    fn base64_matches_reference() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(b"user:pass"), "dXNlcjpwYXNz");
    }

    #[test]
    fn clean_scrubbed_text_passes() {
        let (r, _) = setup();
        let t = r.scrub("host canaryhost7 user carolcanary at /home/carolcanary/x on 10.1.2.3\nplain line\n");
        assert_eq!(hit(&t), None, "{t}");
    }

    #[test]
    fn canary_hostname_user_home() {
        assert!(hit("ok\nthe host is canaryhost7 today\n").unwrap().line == 2);
        assert!(hit("CANARYHOST7").is_some());
        assert!(hit("owner carolcanary").is_some());
        assert!(hit("cd /home/carolcanary/src").is_some());
        assert!(hit("C:\\Users\\carolcanary\\AppData").is_some());
        // a short host name only as a whole word
        assert_eq!(hit("php3 hp30 x-hp3y"), None);
        assert!(hit("ssh hp3 uptime").is_some());
    }

    #[test]
    fn canary_encodings() {
        let v = "carolcanary";
        assert!(hit(&hex::encode(v)).is_some());
        assert!(hit(&hex::encode_upper(v)).is_some());
        for k in 0..3 {
            let mut b = vec![b'Q'; k];
            b.extend_from_slice(v.as_bytes());
            b.extend_from_slice(b"zz");
            let h = hit(&base64(&b)).unwrap_or_else(|| panic!("alignment {k}"));
            assert!(h.reason.contains("base64"), "{}", h.reason);
        }
        assert!(hit("Sup3rS3cretPw").is_some());
        let (r, salt) = setup();
        let sec = vec![Secret { value: "p@ss word/7x".into(), label: "the rpcpassword".into() }];
        let s = Scanner::new(&r, &sec, &salt);
        assert!(s.scan_bytes("f", url_encode("p@ss word/7x").as_bytes()).is_some());
        assert!(s.scan_bytes("f", b"{\"pw\":\"p@ss word\\/7x\"}").is_some());
        let sec = vec![Secret { value: "q\"uote\\d7".into(), label: "the rpcpassword".into() }];
        let s2 = Scanner::new(&r, &sec, &salt);
        assert!(s2.scan_bytes("f", b"{\"pw\":\"q\\\"uote\\\\d7\"}").is_some());
        let mut u16 = b"x\0".to_vec();
        u16.extend(utf16le("p@ss word/7x"));
        assert!(s.scan_bytes("f", &u16).is_some());
    }

    #[test]
    fn canary_rpcpassword_and_cookie() {
        assert!(hit("Invalid -rpcpassword=Sup3rS3cretPw").is_some());
        assert!(hit("rpcpassword=Sup3rS3cretPw").is_some());
        assert!(hit("cookie __cookie__:c00kiec00kiec00kie").is_some());
        let h = hit("Authorization: Basic xSup3rS3cretPw").unwrap();
        assert!(!h.reason.contains("Sup3r"), "the reason never carries the value");
    }

    #[test]
    fn canary_salt_and_machine_id() {
        let (_, salt) = setup();
        assert!(hit(&hex::encode(salt)).unwrap().reason.contains("salt"));
        let mut raw = b"bin ".to_vec();
        raw.extend_from_slice(&salt);
        let (r, s2) = setup();
        assert!(Scanner::new(&r, &[], &s2).scan_bytes("f", &raw).unwrap().reason.contains("raw bytes"));
        assert!(hit("id 0123456789abcdef0123456789abcdef").is_some());
        assert!(hit(&reversed_hex("0123456789abcdef0123456789abcdef").unwrap()).is_some());
    }

    #[test]
    fn redaction_pass_still_changes() {
        let h = hit("a\nb\npeer 203.0.113.9 connected\n").unwrap();
        assert_eq!(h.line, 3);
        assert!(!h.reason.contains("203.0.113.9"), "{}", h.reason);
        assert!(hit("addnode=node7.example.com").is_some());
        assert!(hit("mail bob@example.org").is_some());
        assert!(hit("token=abcdef123456").is_some());
        assert!(hit("{\"auth\": \"abcdef123456\"}").is_some());
        assert!(hit("Computer: canaryhost7").is_some());
        assert!(hit("Name: canaryhost7").is_some());
        assert!(hit("Oct 30 12:00:00 canaryhost7 kernel: x").is_some());
    }

    #[test]
    fn standing_log_lines_are_hits() {
        let h = hit("2026-10-30T12:00:00Z  INFO divi_node::staker: tried stake\n").unwrap();
        assert!(h.reason.contains("staker"), "{}", h.reason);
        assert!(hit("[week of 2026-10-26: UpdateTip: 1000+]\n").is_none());
    }

    #[test]
    fn folder_scan_and_verify() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path();
        fs::create_dir_all(root.join("a")).unwrap();
        fs::write(root.join("a/ok.txt"), "fine\n").unwrap();
        fs::write(root.join("a/bad.txt"), "x\ncanaryhost7\n").unwrap();
        fs::write(root.join(".tmp"), "canaryhost7").unwrap();
        let (r, salt) = setup();
        let hits = Scanner::new(&r, &[], &salt).scan_folder(root);
        assert_eq!(hits, vec![Hit { file: "a/bad.txt".into(), line: 2, reason: "a known host name is still in the file".into() }]);

        let h = crate::util::sha256_file(&root.join("a/ok.txt")).unwrap();
        fs::remove_file(root.join("a/bad.txt")).unwrap();
        fs::write(root.join("02-manifest.txt"), format!("# path\tsize\tsha256\tcollector\na/ok.txt\t5\t{h}\tx\n")).unwrap();
        assert_eq!(verify_sha(root).unwrap(), Vec::<String>::new());
        fs::write(root.join("a/ok.txt"), "fine!\n").unwrap();
        fs::write(root.join("a/new.txt"), "n\n").unwrap();
        assert_eq!(verify_sha(root).unwrap().len(), 2);
    }

    #[test]
    fn secrets_from_conf_and_cookie() {
        let d = tempfile::tempdir().unwrap();
        let c = d.path().join("divi.conf");
        fs::write(&c, "rpcuser=alicerpc\nrpcpassword=dtpass99\n").unwrap();
        let k = d.path().join(".cookie");
        fs::write(&k, "__cookie__:abc123abc123\n").unwrap();
        let s = secrets_of(&[c], &[k]);
        let v: Vec<&str> = s.iter().map(|x| x.value.as_str()).collect();
        assert!(v.contains(&"dtpass99") && v.contains(&"alicerpc") && v.contains(&"abc123abc123"));
        assert!(v.contains(&base64(b"alicerpc:dtpass99").as_str()));
    }
}
