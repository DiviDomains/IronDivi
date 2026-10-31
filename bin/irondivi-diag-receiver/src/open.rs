// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! `irondivi-diag-open`: the developer's side of §9.
//!
//! ```text
//! irondivi-diag-open <ticket> [--out DIR]     download, decrypt, check, unpack
//! irondivi-diag-open --file X.age [--out DIR] the same for a package sent by hand (§8.4)
//! irondivi-diag-open --list                   tickets waiting on the receiver
//! irondivi-diag-open --close <ticket>         delete it from the receiver
//! ```
//!
//! Secrets are resolved once each through `secret get`, never taken on the
//! command line and never printed:
//! - the age identity: `op://global_secret_store/irondivi_diag/age_identity`
//! - the download token: `op://global_secret_store/irondivi_diag_receiver/download_token`
//!
//! `--secrets-stdin` reads them from stdin instead (identity on line 1,
//! token on line 2), for a host without `secret`, e.g.
//! `{ secret get …identity; secret get …token; } | ssh host irondivi-diag-open --secrets-stdin T`.
//!
//! After unpacking it checks every file against `02-manifest.txt` and then
//! runs `irondivi-replay <dir>` if that program is on PATH.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::str::FromStr;

use divi_diag::tar::{read_all, Member};
use irondivi_diag_receiver::is_ticket;
use sha2::{Digest, Sha256};

const DEFAULT_URL: &str = "https://diag.irondivi.com";
const IDENTITY: (&str, &str) = ("irondivi_diag_age_identity", "op://global_secret_store/irondivi_diag/age_identity");
const TOKEN: (&str, &str) = ("irondivi_diag_download_token", "op://global_secret_store/irondivi_diag_receiver/download_token");
const MANIFEST: &str = "02-manifest.txt";
/// Unpack limits: the receiver takes 100 MiB compressed; allow 4 GiB out
const PER_FILE: u64 = 2 << 30;
const TOTAL: u64 = 4 << 30;

struct Args {
    ticket: Option<String>,
    file: Option<PathBuf>,
    out: Option<PathBuf>,
    url: String,
    list: bool,
    close: Option<String>,
    stdin: bool,
}

fn usage() -> ! {
    eprintln!(
        "usage: irondivi-diag-open <ticket> [--out DIR] [--url URL] [--secrets-stdin]\n\
         \x20      irondivi-diag-open --file PACKAGE.age [--out DIR] [--secrets-stdin]\n\
         \x20      irondivi-diag-open --list | --close <ticket> [--url URL] [--secrets-stdin]"
    );
    std::process::exit(2)
}

fn parse() -> Args {
    let mut a = Args {
        ticket: None,
        file: None,
        out: None,
        url: std::env::var("DIAG_RECEIVER_URL").unwrap_or_else(|_| DEFAULT_URL.into()),
        list: false,
        close: None,
        stdin: false,
    };
    let mut it = std::env::args().skip(1);
    while let Some(x) = it.next() {
        match x.as_str() {
            "--file" => a.file = Some(it.next().unwrap_or_else(|| usage()).into()),
            "--out" => a.out = Some(it.next().unwrap_or_else(|| usage()).into()),
            "--url" => a.url = it.next().unwrap_or_else(|| usage()),
            "--list" => a.list = true,
            "--close" => a.close = Some(it.next().unwrap_or_else(|| usage()).to_ascii_uppercase()),
            "--secrets-stdin" => a.stdin = true,
            "-h" | "--help" => usage(),
            t if !t.starts_with('-') && a.ticket.is_none() => a.ticket = Some(t.to_ascii_uppercase()),
            _ => usage(),
        }
    }
    a
}

fn die(msg: &str) -> ! {
    eprintln!("irondivi-diag-open: {msg}");
    std::process::exit(1)
}

/// `secret get`, once; the value never reaches argv or the terminal
fn secret_get(name: &str, op_ref: &str) -> String {
    let out = Command::new("secret")
        .args(["get", "--name", name, "--op-ref", op_ref])
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| die(&format!("cannot run `secret` ({}); on a host without it use --secrets-stdin", e.kind())));
    if !out.status.success() || out.stdout.is_empty() {
        die(&format!("`secret get` did not resolve {op_ref} (exit {:?})", out.status.code()));
    }
    String::from_utf8(out.stdout).unwrap_or_else(|_| die("the secret is not text")).trim().to_string()
}

struct Secrets {
    identity: Option<String>,
    token: Option<String>,
}

fn secrets(a: &Args, need_identity: bool, need_token: bool) -> Secrets {
    if a.stdin {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).unwrap_or_else(|_| die("cannot read stdin"));
        // an age key file's `# created` / `# public key` lines are skipped
        let mut l = s.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
        let mut identity = None;
        let mut token = None;
        if need_identity {
            identity = Some(l.next().unwrap_or_else(|| die("--secrets-stdin: no identity on line 1")).to_string());
        }
        if need_token {
            token = Some(l.next().unwrap_or_else(|| die("--secrets-stdin: no token")).to_string());
        }
        return Secrets { identity, token };
    }
    Secrets {
        identity: need_identity.then(|| secret_get(IDENTITY.0, IDENTITY.1)),
        token: need_token.then(|| secret_get(TOKEN.0, TOKEN.1)),
    }
}

fn client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(600))
        .build()
        .unwrap_or_else(|e| die(&format!("http client: {e}")))
}

fn dev(url: &str, path: &str) -> String {
    format!("{}/v1/dev{path}", url.trim_end_matches('/'))
}

fn main() {
    let a = parse();
    let n_modes = [a.ticket.is_some(), a.file.is_some(), a.list, a.close.is_some()].iter().filter(|x| **x).count();
    if n_modes != 1 {
        usage();
    }
    if a.list {
        let s = secrets(&a, false, true);
        let r = client().get(dev(&a.url, "")).bearer_auth(s.token.unwrap_or_default()).send();
        let r = r.unwrap_or_else(|e| die(&format!("{e}")));
        let code = r.status();
        let body = r.text().unwrap_or_default();
        if !code.is_success() {
            die(&format!("{code}: {}", body.trim()));
        }
        println!("{body}");
        return;
    }
    if let Some(t) = &a.close {
        if !is_ticket(t) {
            die("not a ticket: 8 characters from 0-9 A-Z without I L O U");
        }
        let s = secrets(&a, false, true);
        let r = client().delete(dev(&a.url, &format!("/{t}"))).bearer_auth(s.token.unwrap_or_default()).send();
        let r = r.unwrap_or_else(|e| die(&format!("{e}")));
        let code = r.status();
        let body = r.text().unwrap_or_default();
        if !code.is_success() {
            die(&format!("{code}: {}", body.trim()));
        }
        println!("{t}: {}", body.trim());
        return;
    }

    let (label, ciphertext, s) = if let Some(t) = &a.ticket {
        if !is_ticket(t) {
            die("not a ticket: 8 characters from 0-9 A-Z without I L O U");
        }
        let s = secrets(&a, true, true);
        let r = client()
            .get(dev(&a.url, &format!("/{t}")))
            .bearer_auth(s.token.as_deref().unwrap_or_default())
            .send()
            .unwrap_or_else(|e| die(&format!("download: {e}")));
        let code = r.status();
        let want = r.headers().get("x-diag-sha256").and_then(|v| v.to_str().ok()).map(str::to_string);
        let body = r.bytes().unwrap_or_else(|e| die(&format!("download: {e}"))).to_vec();
        if !code.is_success() {
            die(&format!("download: {code}: {}", String::from_utf8_lossy(&body).trim()));
        }
        let got = hex::encode(Sha256::digest(&body));
        match want {
            Some(w) if w == got => println!("downloaded {t}: {} bytes, sha256 {got} (matches the receiver's record)", body.len()),
            Some(w) => die(&format!("download damaged: sha256 {got}, the receiver recorded {w}")),
            None => die("the receiver sent no sha256 header"),
        }
        (t.clone(), body, s)
    } else {
        let f = a.file.clone().unwrap_or_else(|| usage());
        let body = std::fs::read(&f).unwrap_or_else(|e| die(&format!("{}: {}", f.display(), e.kind())));
        println!("read {}: {} bytes, sha256 {}", f.display(), body.len(), hex::encode(Sha256::digest(&body)));
        let label = f.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "package".into());
        (label, body, secrets(&a, true, false))
    };

    // the stored identity is a whole age key file: comments, then the key
    let key_line = s.identity.as_deref().unwrap_or_default().lines().map(str::trim).find(|l| l.starts_with("AGE-SECRET-KEY-"));
    let identity = age::x25519::Identity::from_str(key_line.unwrap_or_default())
        .unwrap_or_else(|_| die("the age identity does not parse (expected AGE-SECRET-KEY-1…)"));
    drop(s);
    let tar = open_package(&ciphertext, &identity).unwrap_or_else(|e| die(&e));
    let members = read_all(&mut tar.as_slice(), PER_FILE, TOTAL).unwrap_or_else(|e| die(&format!("unpacking: {e}")));

    let out = a.out.clone().unwrap_or_else(|| PathBuf::from(format!("diag-{label}")));
    if out.exists() {
        die(&format!("{} exists; pass --out to choose another", out.display()));
    }
    create_private_dir(&out).unwrap_or_else(|e| die(&format!("{}: {e}", out.display())));
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    for m in members {
        match m {
            Member::File { name, data } => {
                let p = safe_join(&out, &name).unwrap_or_else(|| die(&format!("refusing member path {name:?}")));
                if let Some(d) = p.parent() {
                    std::fs::create_dir_all(d).unwrap_or_else(|e| die(&format!("{}: {e}", d.display())));
                }
                std::fs::write(&p, &data).unwrap_or_else(|e| die(&format!("{}: {e}", p.display())));
                files.push((name, data));
            }
            Member::Skipped { name, why } => println!("skipped member {name}: {why}"),
        }
    }
    println!("unpacked {} files into {}", files.len(), out.display());

    let ok = check_manifest(&files);
    match which("irondivi-replay") {
        Some(p) => {
            println!("running {} {}", p.display(), out.display());
            let st = Command::new(p).arg(&out).status();
            match st {
                Ok(s) if s.success() => {}
                Ok(s) => println!("irondivi-replay exited {:?}", s.code()),
                Err(e) => println!("irondivi-replay did not start: {}", e.kind()),
            }
        }
        None => println!("irondivi-replay: not installed (it does not exist yet); the files are unpacked for reading by hand"),
    }
    let _ = std::io::stdout().flush();
    std::process::exit(if ok { 0 } else { 3 });
}

/// age (X25519) → zstd → the tar bytes
fn open_package(ciphertext: &[u8], identity: &age::x25519::Identity) -> Result<Vec<u8>, String> {
    let d = age::Decryptor::new(ciphertext).map_err(|e| format!("not an age file: {e}"))?;
    let mut r = d
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| format!("decrypt failed (wrong key, or damaged): {e}"))?;
    let mut z = Vec::new();
    r.read_to_end(&mut z).map_err(|e| format!("decrypt failed (damaged): {}", e.kind()))?;
    let mut tar = Vec::new();
    zstd::stream::read::Decoder::new(z.as_slice())
        .and_then(|mut dec| dec.read_to_end(&mut tar))
        .map_err(|e| format!("decompressing: {}", e.kind()))?;
    Ok(tar)
}

/// Every manifest line against the unpacked bytes. `true` when all match.
fn check_manifest(files: &[(String, Vec<u8>)]) -> bool {
    let Some((_, m)) = files.iter().find(|(n, _)| n == MANIFEST) else {
        println!("manifest: MISSING ({MANIFEST} is not in the package)");
        return false;
    };
    let text = String::from_utf8_lossy(m);
    let mut good = 0;
    let mut bad = 0;
    let mut absent = 0;
    for l in text.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()) {
        let f: Vec<&str> = l.split('\t').collect();
        if f.len() < 3 {
            continue;
        }
        let (rel, size, sha) = (f[0], f[1], f[2]);
        match files.iter().find(|(n, _)| n == rel) {
            Some((_, d)) => {
                let got = hex::encode(Sha256::digest(d));
                if got == sha && size.parse::<usize>().ok() == Some(d.len()) {
                    good += 1;
                } else {
                    bad += 1;
                    println!("manifest: MISMATCH {rel}: size {} sha256 {got}, manifest says {size} {sha}", d.len());
                }
            }
            None => {
                absent += 1;
                println!("manifest: not in the package (left out at review): {rel}");
            }
        }
    }
    let extra: Vec<&str> = files
        .iter()
        .map(|(n, _)| n.as_str())
        .filter(|n| *n != MANIFEST && !text.lines().any(|l| l.split('\t').next() == Some(*n)))
        .collect();
    for n in &extra {
        println!("manifest: UNLISTED file in the package: {n}");
    }
    println!("manifest: {good} files match, {bad} mismatched, {absent} left out, {} unlisted", extra.len());
    bad == 0 && extra.is_empty()
}

fn safe_join(root: &Path, name: &str) -> Option<PathBuf> {
    let p = Path::new(name);
    if p.is_absolute() || p.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return None;
    }
    Some(root.join(p))
}

fn create_private_dir(p: &Path) -> std::io::Result<()> {
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
    b.create(p)
}

fn which(prog: &str) -> Option<PathBuf> {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).map(|d| d.join(prog)).find(|c| c.is_file()))
        .unwrap_or(None)
}
