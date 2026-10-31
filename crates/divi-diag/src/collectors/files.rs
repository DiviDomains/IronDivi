// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B1.2 binaries, B1.3 config files, B2.9 wallet (config part) and B2.19
//! package and install.

use super::{cmd_block_t, head, LINUX};
use crate::ctx::Ctx;
use crate::frame::Out;
use crate::outln;
use crate::redact::Redactor;
use crate::settings::Settings;
use crate::util;
use sha2::{Digest, Sha256};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const PROGRAMS: &[&str] = &["irondivid", "irondivi-cli"];

// ---------------------------------------------------------------- B1.2

/// What the header of an executable says
#[derive(Debug, Default, PartialEq)]
pub struct BinInfo {
    pub format: String,
    pub machine: String,
    /// `PT_INTERP`; `None` for a static ELF
    pub interp: Option<String>,
    pub build_id: Option<String>,
}

fn rd(b: &[u8], off: usize, n: usize, le: bool) -> Option<u64> {
    let s = b.get(off..off + n)?;
    let mut v = 0u64;
    for i in 0..n {
        let byte = if le { s[n - 1 - i] } else { s[i] } as u64;
        v = (v << 8) | byte;
    }
    Some(v)
}

fn elf_machine(m: u64) -> String {
    match m {
        3 => "i386".into(),
        62 => "x86_64".into(),
        40 => "arm".into(),
        183 => "aarch64".into(),
        20 => "powerpc".into(),
        21 => "powerpc64".into(),
        22 => "s390".into(),
        243 => "riscv".into(),
        8 => "mips".into(),
        other => format!("machine {other}"),
    }
}

fn macho_cpu(c: u64) -> String {
    match c {
        0x0100_0007 => "x86_64".into(),
        0x0100_000c => "arm64".into(),
        7 => "i386".into(),
        12 => "arm".into(),
        other => format!("cputype {other:#x}"),
    }
}

/// ELF or Mach-O header facts, from the file's bytes
pub fn bin_info(b: &[u8]) -> Option<BinInfo> {
    if b.starts_with(b"\x7fELF") {
        let class64 = *b.get(4)? == 2;
        let le = *b.get(5)? == 1;
        let mut i = BinInfo {
            format: format!("ELF {}-bit {}", if class64 { 64 } else { 32 }, if le { "LSB" } else { "MSB" }),
            machine: elf_machine(rd(b, 18, 2, le)?),
            ..Default::default()
        };
        let (phoff, phentsize, phnum) = if class64 {
            (rd(b, 32, 8, le)?, rd(b, 54, 2, le)?, rd(b, 56, 2, le)?)
        } else {
            (rd(b, 28, 4, le)?, rd(b, 42, 2, le)?, rd(b, 44, 2, le)?)
        };
        for k in 0..phnum.min(256) {
            let h = (phoff + k * phentsize) as usize;
            let ty = rd(b, h, 4, le)?;
            let (off, sz) = if class64 {
                (rd(b, h + 8, 8, le)? as usize, rd(b, h + 32, 8, le)? as usize)
            } else {
                (rd(b, h + 4, 4, le)? as usize, rd(b, h + 16, 4, le)? as usize)
            };
            let Some(seg) = b.get(off..off.saturating_add(sz)) else { continue };
            match ty {
                3 => i.interp = Some(String::from_utf8_lossy(seg).trim_end_matches('\0').to_string()),
                4 => {
                    let mut p = 0usize;
                    while p + 12 <= seg.len() {
                        let namesz = rd(seg, p, 4, le)? as usize;
                        let descsz = rd(seg, p + 4, 4, le)? as usize;
                        let nty = rd(seg, p + 8, 4, le)?;
                        let name_at = p + 12;
                        let desc_at = name_at + namesz.div_ceil(4) * 4;
                        if nty == 3 && seg.get(name_at..name_at + namesz) == Some(b"GNU\0") {
                            if let Some(d) = seg.get(desc_at..desc_at + descsz) {
                                i.build_id = Some(hex::encode(d));
                            }
                        }
                        p = desc_at + descsz.div_ceil(4) * 4;
                    }
                }
                _ => {}
            }
        }
        return Some(i);
    }
    let magic = rd(b, 0, 4, false)?;
    if magic == 0xcafe_babe {
        let n = rd(b, 4, 4, false)?;
        let archs: Vec<String> = (0..n.min(8)).filter_map(|k| rd(b, 8 + k as usize * 20, 4, false).map(macho_cpu)).collect();
        return Some(BinInfo { format: "Mach-O universal".into(), machine: archs.join("+"), interp: None, build_id: None });
    }
    if magic == 0xcffa_edfe || magic == 0xcefa_edfe {
        let is64 = magic == 0xcffa_edfe;
        let mut i = BinInfo {
            format: format!("Mach-O {}-bit", if is64 { 64 } else { 32 }),
            machine: macho_cpu(rd(b, 4, 4, true)?),
            ..Default::default()
        };
        let ncmds = rd(b, 16, 4, true)?;
        let mut p = if is64 { 32 } else { 28 };
        for _ in 0..ncmds.min(512) {
            let cmd = rd(b, p, 4, true)?;
            let size = rd(b, p + 4, 4, true)? as usize;
            if cmd == 0x1b {
                if let Some(u) = b.get(p + 8..p + 24) {
                    i.build_id = Some(format!("uuid {}", hex::encode(u)));
                }
            }
            if cmd == 0xe {
                // LC_LOAD_DYLINKER
                if let Some(off) = rd(b, p + 8, 4, true) {
                    if let Some(s) = b.get(p + off as usize..p + size) {
                        i.interp = Some(String::from_utf8_lossy(s).trim_end_matches('\0').to_string());
                    }
                }
            }
            if size == 0 {
                break;
            }
            p += size;
        }
        return Some(i);
    }
    None
}

/// Every irondivi program this host has where diag looks: PATH, the
/// usual install dirs, next to diag, the running nodes, and the homes of
/// the data dirs' owners (`~/bin`, `~/.local/bin`, `~/.cargo/bin`, release
/// folders under `~` and `/opt` one level down)
pub fn copies(ctx: &Ctx) -> Vec<(PathBuf, String)> {
    let mut dirs: Vec<(PathBuf, String)> = Vec::new();
    if let Some(p) = std::env::var_os("PATH") {
        for d in std::env::split_paths(&p) {
            dirs.push((d, "PATH".into()));
        }
    }
    for d in ["/usr/local/bin", "/usr/bin", "/opt/irondivi/bin", "/opt/irondivi", "/usr/local/irondivi/bin", "/opt/homebrew/bin"] {
        dirs.push((d.into(), "standard dir".into()));
    }
    if let Ok(me) = std::env::current_exe() {
        if let Some(d) = me.parent() {
            dirs.push((d.to_path_buf(), "next to diag".into()));
        }
    }
    let mut homes: Vec<PathBuf> = Vec::new();
    for uid in ctx.datadirs.iter().filter_map(|d| d.owner).chain(std::iter::once(util::uid())) {
        if let Some(h) = util::user_home(uid) {
            if !homes.contains(&h) {
                homes.push(h);
            }
        }
    }
    // every home this user can list (all of them under sudo)
    for base in ["/home", "/Users", "/root"] {
        let entries: Vec<PathBuf> = if base == "/root" {
            vec![PathBuf::from(base)]
        } else {
            std::fs::read_dir(base).map(|rd| rd.flatten().map(|e| e.path()).collect()).unwrap_or_default()
        };
        for h in entries {
            if h.is_dir() && !homes.contains(&h) {
                homes.push(h);
            }
        }
    }
    for h in &homes {
        for sub in ["bin", ".local/bin", ".cargo/bin"] {
            dirs.push((h.join(sub), "home".into()));
        }
    }
    // release folders: one level below ~ and /opt whose name starts with irondivi
    for base in homes.iter().cloned().chain([PathBuf::from("/opt"), PathBuf::from("/usr/local")]) {
        if let Ok(rd) = std::fs::read_dir(&base) {
            for e in rd.flatten() {
                if e.file_name().to_string_lossy().to_ascii_lowercase().starts_with("irondivi") && e.path().is_dir() {
                    dirs.push((e.path(), "release folder".into()));
                    dirs.push((e.path().join("bin"), "release folder".into()));
                }
            }
        }
    }
    let mut out: Vec<(PathBuf, String)> = Vec::new();
    let push = |p: PathBuf, why: String, out: &mut Vec<(PathBuf, String)>| {
        let c = p.canonicalize().unwrap_or(p.clone());
        if let Some(x) = out.iter_mut().find(|(q, _)| q.canonicalize().unwrap_or(q.clone()) == c) {
            if !x.1.contains(&why) {
                x.1 = format!("{}, {why}", x.1);
            }
        } else {
            out.push((p, why));
        }
    };
    for (d, why) in dirs {
        for prog in PROGRAMS {
            let p = d.join(prog);
            if p.is_file() {
                push(p, why.clone(), &mut out);
            }
        }
    }
    for n in &ctx.nodes {
        if let Some(e) = &n.exe {
            let s = e.to_string_lossy();
            let p = PathBuf::from(s.trim_end_matches(" (deleted)"));
            push(p, format!("running pid {}", n.pid), &mut out);
        }
    }
    out
}

fn describe(o: &mut Out, r: &Redactor, p: &Path, why: &str) -> Option<String> {
    head(o, &format!("{} ({why})", r.path_of(p)));
    let md = match std::fs::metadata(p) {
        Ok(m) => m,
        Err(e) => {
            outln!(o, "{}", util::io_err(&e));
            return None;
        }
    };
    outln!(o, "size {}  mtime {}  mode {:o}  owner {}", md.len(), util::rfc3339(md.mtime()), md.mode() & 0o7777, owner_name(r, md.uid()));
    let bytes = match util::read_bytes_capped(p, 512 << 20) {
        Ok(b) => b,
        Err(e) => {
            outln!(o, "read: {}", util::io_err(&e));
            return None;
        }
    };
    let sum = hex::encode(Sha256::digest(&bytes));
    outln!(o, "sha256:{sum}");
    match bin_info(&bytes) {
        Some(i) => {
            outln!(o, "format {}  machine {}", i.format, i.machine);
            match (&i.interp, i.format.starts_with("ELF")) {
                (Some(x), _) => outln!(o, "interpreter {x}"),
                (None, true) => outln!(o, "interpreter none (static)"),
                _ => {}
            }
            outln!(o, "build-id {}", i.build_id.as_deref().unwrap_or("(none)"));
            outln!(o, "build-id in the release list: not checked (no release list is compiled into this diag yet)");
        }
        None => outln!(o, "not an ELF or Mach-O executable"),
    }
    let v = util::run_cmd(&p.to_string_lossy(), &["--version"], Duration::from_secs(5), 16 << 10);
    if let Some(e) = &v.spawn_error {
        outln!(o, "--version: exec failed: {e}");
    } else {
        if !v.ok() {
            outln!(o, "--version: [{}]", v.status_line());
        }
        for l in v.text().lines().take(3) {
            outln!(o, "--version: {l}");
        }
        for l in util::escape_bytes(&v.stderr).lines().take(5) {
            outln!(o, "--version stderr: {l}");
        }
    }
    if !LINUX {
        let ps = p.to_string_lossy().to_string();
        // B4.2: attribute names only, never their values
        let x = util::run_cmd("xattr", &[&ps], Duration::from_secs(5), 16 << 10);
        outln!(o, "xattr: {}", if x.text().trim().is_empty() { "(none)".into() } else { x.text().split_whitespace().collect::<Vec<_>>().join(" ") });
        let c = util::run_cmd("codesign", &["-dv", &ps], Duration::from_secs(5), 16 << 10);
        for l in util::escape_bytes(&c.stderr).lines().filter(|l| !l.starts_with("Executable=")).take(12) {
            outln!(o, "codesign: {l}");
        }
        let s = util::run_cmd("spctl", &["--assess", "--type", "execute", &ps], Duration::from_secs(10), 16 << 10);
        outln!(o, "spctl: {} {}", s.status_line(), util::escape_bytes(&s.stderr).replace(&ps, "<this file>").trim());
    }
    Some(sum)
}

fn owner_name(r: &Redactor, uid: u32) -> String {
    if uid == 0 {
        "root".into()
    } else {
        r.user(&util::user_name(uid).unwrap_or_else(|| uid.to_string()))
    }
}

/// B1.2
pub fn binaries(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("binaries.txt");
    let found = copies(ctx);
    if found.is_empty() {
        outln!(o, "no irondivid or irondivi-cli found");
    }
    let mut sums: Vec<(PathBuf, Option<String>)> = Vec::new();
    for (p, why) in &found {
        let s = describe(o, &r, p, why);
        sums.push((p.clone(), s));
    }
    head(o, "running vs on disk (L3)");
    if ctx.nodes.is_empty() {
        outln!(o, "no node running");
    }
    for n in &ctx.nodes {
        let link = PathBuf::from(format!("/proc/{}/exe", n.pid));
        let target = std::fs::read_link(&link).ok();
        let running = if LINUX {
            util::read_bytes_capped(&link, 512 << 20).ok().map(|b| hex::encode(Sha256::digest(&b)))
        } else {
            None
        };
        let path = target.clone().or_else(|| n.exe.clone());
        let deleted = path.as_ref().is_some_and(|p| p.to_string_lossy().ends_with(" (deleted)"));
        let disk_path = path.as_ref().map(|p| PathBuf::from(p.to_string_lossy().trim_end_matches(" (deleted)")));
        let source = if target.is_some() { "/proc exe link" } else if n.exe.is_some() { "from path record" } else { "unknown" };
        let disk = disk_path.as_ref().and_then(|p| sums.iter().find(|(q, _)| q == p).and_then(|x| x.1.clone()).or_else(|| util::sha256_file(p).ok()));
        outln!(o, "pid {}: {} ({source}){}", n.pid, disk_path.as_ref().map(|p| r.path_of(p)).unwrap_or_else(|| "(not known)".into()), if deleted { " [deleted]" } else { "" });
        match (&running, &disk) {
            (Some(a), Some(b)) if a == b => outln!(o, "  binary on disk matches the running one (sha256:{a})"),
            (Some(a), Some(b)) => outln!(o, "  running binary differs from the file on disk: running sha256:{a}, on disk sha256:{b}"),
            (Some(a), None) => outln!(o, "  running binary differs from the file on disk: running sha256:{a}, the file is gone"),
            (None, Some(b)) => outln!(
                o,
                "  the running image could not be read ({}); file now at that path sha256:{b}",
                if LINUX { "no permission on /proc/<pid>/exe" } else { "macOS has no /proc" }
            ),
            (None, None) => outln!(o, "  neither the running image nor the file could be read"),
        }
    }
}

// ---------------------------------------------------------------- B1.3

/// §6.2: keys whose value is a secret
pub fn secret_key(k: &str) -> bool {
    let k = k.to_ascii_lowercase();
    const PUBLIC_KEYS: &[&str] = &["spendkey", "pubkey"];
    if PUBLIC_KEYS.contains(&k.as_str()) {
        return false;
    }
    ["rpcpassword", "rpcuser", "rpcauth", "masternodeprivkey"].contains(&k.as_str())
        || (k.starts_with("electrum") && k.ends_with("key"))
        || ["password", "token", "secret", "key", "seed", "mnemonic", "passphrase", "cookie"].iter().any(|s| k.contains(s))
}

/// §6.2: known non-secret keys whose values are shown (paths and
/// addresses are pseudonymised by the scrub; host names here)
const SHOWN_KEYS: &[&str] = &[
    "datadir", "conf", "pid", "port", "rpcport", "bind", "rpcbind", "rpcallowip", "externalip", "addnode", "connect",
    "seednode", "whitelist", "onlynet", "proxy", "onion", "tor", "maxconnections", "dbcache", "par", "txindex",
    "spentindex", "addressindex", "server", "rest", "daemon", "testnet", "regtest", "staking", "listen", "upnp",
    "discover", "dns", "dnsseed", "debug", "loglevel", "printtoconsole", "logtimestamps", "logips", "disablewallet",
    "walletbroadcast", "createwalletbackups", "masternode", "masternodeaddr", "reservebalance", "stakesplitthreshold",
    "zmqpubhashblock", "zmqpubhashtx", "zmqpubrawblock", "zmqpubrawtx", "maxmempool", "mempoolexpiry", "prune",
    "reindex", "checkblocks", "checklevel", "rpcthreads", "rpcworkqueue", "timeout", "banscore", "bantime",
    "maxuploadtarget", "blocksonly", "litemode", "shrinkdebugfile", "keypool", "spendzeroconfchange", "minrelaytxfee",
    "paytxfee", "mintxfee", "maxtxfee", "alertnotify", "blocknotify", "walletnotify", "electrum", "electrumport",
    "electrumbind", "webui", "webuiport", "webuibind", "dbbackend", "storage",
];

const HOST_KEYS: &[&str] = &["addnode", "connect", "seednode", "externalip", "proxy", "onion", "bind", "rpcbind", "masternodeaddr", "electrumbind", "webuibind", "electrum", "electrumws", "electrumtls", "electrumwss"];
const COMMAND_KEYS: &[&str] = &["alertnotify", "blocknotify", "walletnotify"];

pub(crate) fn host_value(r: &Redactor, v: &str) -> String {
    let host = v.rsplit_once(':').filter(|(h, p)| !h.ends_with(':') && p.chars().all(|c| c.is_ascii_digit())).map(|x| x.0).unwrap_or(v);
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if bare.parse::<std::net::IpAddr>().is_ok() || bare.is_empty() {
        v.to_string() // the scrub classes IPs
    } else {
        v.replacen(host, &r.pseudonym("host", host), 1)
    }
}

/// One config value rendered per §6.2
pub fn render_value(r: &Redactor, key: &str, value: &str) -> Option<String> {
    let k = key.to_ascii_lowercase();
    if secret_key(&k) {
        return Some(if value.is_empty() { "<unset>".into() } else { "<set>".into() });
    }
    if k == "wallet" {
        return Some(r.pseudonym("walletfile", value));
    }
    if COMMAND_KEYS.contains(&k.as_str()) {
        let argv: Vec<String> = value.split_whitespace().map(str::to_string).collect();
        return Some(super::procs::mask_argv(&argv));
    }
    if HOST_KEYS.contains(&k.as_str()) {
        return Some(host_value(r, value));
    }
    if SHOWN_KEYS.contains(&k.as_str()) || super::procs::ARGV_ALLOW.contains(&k.as_str()) {
        return Some(value.to_string());
    }
    None
}

fn conf_files(ctx: &Ctx) -> Vec<(usize, PathBuf)> {
    let mut v: Vec<(usize, PathBuf)> = Vec::new();
    for d in &ctx.datadirs {
        let mut cands: Vec<PathBuf> = vec![d.path.join("irondivi.conf"), d.path.join("divi.conf"), d.chain.join("irondivi.conf"), d.path.join("masternode.conf"), d.chain.join("masternode.conf")];
        if let Some(c) = &d.conf {
            cands.insert(0, c.clone());
        }
        if let Some(n) = ctx.node_for(d) {
            if let Some(c) = &n.conf {
                cands.insert(0, c.clone());
            }
        }
        for c in cands {
            if c.is_file() && !v.iter().any(|(_, x)| x == &c) {
                v.push((d.n, c));
            }
        }
    }
    v
}

/// B1.3
pub fn config(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    let files = conf_files(ctx);
    if files.is_empty() {
        o.file("diag.log");
        outln!(o, "config: no irondivi.conf, divi.conf or masternode.conf found next to any data dir");
    }
    for (n, p) in files {
        let name = p.file_name().map(|x| x.to_string_lossy().to_string()).unwrap_or_default();
        let mut k = 1;
        let mut rel = format!("datadir-{n}/config/{name}");
        while rel_taken(&rel, k) {
            k += 1;
            rel = format!("datadir-{n}/config/{name}.{k}");
        }
        o.file(&rel);
        outln!(o, "# {} (rendered per §6.2; secret values show <set>/<unset>, unknown keys their name only)", r.path_of(&p));
        if let Ok(md) = std::fs::metadata(&p) {
            outln!(
                o,
                "# mode {:o}  owner {}  size {}  mtime {}{}",
                md.mode() & 0o7777,
                owner_name(&r, md.uid()),
                md.len(),
                util::rfc3339(md.mtime()),
                if md.mode() & 0o004 != 0 { "  (readable by every user)" } else { "" }
            );
        }
        let text = match util::read_bytes_capped(&p, 4 << 20) {
            Ok(b) => String::from_utf8_lossy(&b).to_string(),
            Err(e) => {
                outln!(o, "# unreadable: {}{}", util::io_err(&e), crate::discovery::sudo_hint(std::fs::metadata(&p).ok().map(|m| m.uid()), &p));
                continue;
            }
        };
        if name == "masternode.conf" {
            render_masternode(&r, &text, o);
        } else {
            render_conf(&r, &text, o);
        }
    }
}

// Out has no "has this file" query; config writes at most a few files, so
// a per-process set is enough
fn rel_taken(rel: &str, _k: usize) -> bool {
    use std::sync::Mutex;
    static SEEN: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let mut s = SEEN.lock().unwrap();
    if s.iter().any(|x| x == rel) {
        true
    } else {
        s.push(rel.to_string());
        false
    }
}

pub fn render_conf(r: &Redactor, text: &str, o: &mut Out) {
    let mut s = Settings::default();
    if let Err(e) = s.read_config(text) {
        outln!(o, "# the node's parser stops here: {e}");
    }
    // Line by line, so the order and sections are kept; each key
    // re-read through the node's parser rules (prefix, section, dashes)
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            outln!(o, "{line}");
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            outln!(o, "<line that is not key=value>");
            continue;
        };
        let key = key.trim();
        let bare = key.rsplit('.').next().unwrap_or(key).trim_start_matches('-');
        match render_value(r, bare, value.trim()) {
            Some(v) => outln!(o, "{key}={v}"),
            None => outln!(o, "{key}  (unknown key; value not shown)"),
        }
    }
    if !s.stray.is_empty() {
        outln!(o, "# {} words that are not options", s.stray.len());
    }
}

/// `alias ip:port privkey txid index`: the alias pseudonym and the field count
pub fn render_masternode(r: &Redactor, text: &str, o: &mut Out) {
    let mut n = 0;
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        n += 1;
        let f: Vec<&str> = l.split_whitespace().collect();
        outln!(o, "{}  ({} fields)", r.pseudonym("mn", f[0]), f.len());
    }
    outln!(o, "# {n} entries");
}

// ---------------------------------------------------------------- B2.9

/// B2.9, the part diag can do without B2.16: what the config says
pub fn wallet(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    for d in &ctx.datadirs {
        o.file(&format!("datadir-{}/wallet-structure.txt", d.n));
        outln!(o, "Diag never opens the wallet store (§6.1). Facts from the config:");
        let conf = d.conf.clone().or_else(|| [d.path.join("irondivi.conf"), d.path.join("divi.conf"), d.chain.join("irondivi.conf")].into_iter().find(|p| p.is_file()));
        let mut s = Settings::default();
        let mut node_args: Vec<String> = Vec::new();
        if let Some(n) = ctx.node_for(d) {
            node_args = n.argv.iter().skip(1).cloned().collect();
        }
        match conf.as_ref().map(|c| std::fs::read_to_string(c)) {
            Some(Ok(t)) => {
                if let Err(e) = s.read_config(&t) {
                    outln!(o, "config parse: {e}");
                }
            }
            Some(Err(e)) => outln!(o, "config unreadable: {}", util::io_err(&e)),
            None => outln!(o, "no config file"),
        }
        let cli = Settings::from_command_line(&node_args);
        let get = |k: &str| cli.get(k).or_else(|| s.get(k)).map(str::to_string);
        for k in ["disablewallet", "walletbroadcast", "createwalletbackups", "staking", "reservebalance"] {
            outln!(o, "{k}: {}", get(k).unwrap_or_else(|| "(not set)".into()));
        }
        let mut names: Vec<String> = cli.get_multi("wallet").to_vec();
        names.extend(s.get_multi("wallet").iter().cloned());
        if names.is_empty() {
            outln!(o, "wallet=: (not set)");
        }
        for w in names {
            outln!(o, "wallet=: {}", r.pseudonym("walletfile", &w));
        }
        outln!(o, "wallet/ present: {}", if d.path.join("wallet").is_dir() || d.chain.join("wallet").is_dir() { "yes (size in inventory.txt)" } else { "no" });
        outln!(o, "wallet.dat present: {}", if d.path.join("wallet.dat").exists() || d.chain.join("wallet.dat").exists() { "yes" } else { "no" });
        if d.running_pid.is_some() {
            outln!(o, "getdiaginfo wallet section: not collected (B2.16 live node collection is not in this diag version)");
        } else {
            outln!(o, "getdiaginfo wallet section: absent, the node is not running; B3 observed start (when consented) collects it");
        }
    }
    if ctx.datadirs.is_empty() {
        o.file("diag.log");
        outln!(o, "wallet: no data dir found");
    }
}

// ---------------------------------------------------------------- B2.19

/// B2.19
pub fn install(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    o.file("host/install.txt");
    head(o, "package managers");
    let mut any = false;
    let pkg = |o: &mut Out, prog: &str, args: &[&str], any: &mut bool| {
        if util::which(prog).is_none() {
            return;
        }
        let c = util::run_cmd(prog, args, Duration::from_secs(20), 4 << 20);
        let lines: Vec<String> = c.text().lines().filter(|l| l.to_ascii_lowercase().contains("irondivi")).map(str::to_string).collect();
        outln!(o, "$ {prog} {}: {}", args.join(" "), if lines.is_empty() { "no irondivi package".to_string() } else { format!("{} lines", lines.len()) });
        for l in lines.iter().take(20) {
            *any = true;
            outln!(o, "  {l}");
        }
    };
    pkg(o, "dpkg-query", &["-W", "-f", "${Package} ${Version} ${Status}\n"], &mut any);
    pkg(o, "rpm", &["-qa"], &mut any);
    pkg(o, "apk", &["info", "-v"], &mut any);
    pkg(o, "pacman", &["-Q"], &mut any);
    pkg(o, "brew", &["list", "--versions"], &mut any);
    pkg(o, "snap", &["list"], &mut any);
    pkg(o, "flatpak", &["list"], &mut any);
    if !any {
        outln!(o, "no package manager knows an irondivi package");
    }
    // which package owns each copy
    let found = copies(ctx);
    if LINUX && util::which("dpkg-query").is_some() {
        for (p, _) in &found {
            let ps = p.to_string_lossy().to_string();
            let c = util::run_cmd("dpkg-query", &["-S", &ps], Duration::from_secs(10), 64 << 10);
            outln!(o, "dpkg owner of {}: {}", r.path_of(p), if c.ok() { c.text().split(':').next().unwrap_or("").trim().to_string() } else { "none".into() });
        }
    }

    head(o, "docker images");
    let sock = Path::new("/var/run/docker.sock");
    if util::which("docker").is_some() && sock.exists() {
        let c = util::run_cmd("docker", &["images", "--digests", "--format", "{{.Repository}}:{{.Tag}} {{.Digest}} {{.CreatedSince}} {{.Size}}"], Duration::from_secs(15), 1 << 20);
        if !c.ok() {
            outln!(o, "[{}] {}", c.status_line(), util::escape_bytes(&c.stderr).lines().next().unwrap_or(""));
        }
        let mut n = 0;
        for l in c.text().lines().filter(|l| l.to_ascii_lowercase().contains("divi")) {
            n += 1;
            // a locally built image's repository name (a compose project,
            // a folder) is the user's choice: keep only our own names
            let (img, rest) = l.split_once(' ').unwrap_or((l, ""));
            let (repo, tag) = img.rsplit_once(':').unwrap_or((img, ""));
            let last = repo.rsplit('/').next().unwrap_or(repo);
            let repo = if matches!(last, "irondivi" | "irondivid") { repo.to_string() } else { r.pseudonym("image", repo) };
            let tag = if matches!(tag, "latest" | "<none>" | "") || tag.chars().all(|c| c.is_ascii_digit() || c == '.' || c == 'v') { tag.to_string() } else { r.pseudonym("tag", tag) };
            outln!(o, "{repo}:{tag} {rest}");
        }
        if c.ok() && n == 0 {
            outln!(o, "no irondivi image");
        }
    } else {
        outln!(o, "docker not present");
    }

    head(o, "every copy found");
    if found.is_empty() {
        outln!(o, "none");
    }
    for (p, why) in &found {
        match std::fs::metadata(p) {
            Ok(md) => outln!(
                o,
                "{}  ({why})  {}  mode {:o}  owner {}  mtime {}  sha256:{}",
                r.path_of(p),
                util::human(md.len()),
                md.mode() & 0o7777,
                owner_name(&r, md.uid()),
                util::rfc3339(md.mtime()),
                util::sha256_file(p).unwrap_or_else(|e| format!("({})", util::io_err(&e)))
            ),
            Err(e) => outln!(o, "{}  ({why})  {}", r.path_of(p), util::io_err(&e)),
        }
    }

    head(o, "release archives under the data dir owners' homes");
    let mut homes: Vec<PathBuf> = ctx.datadirs.iter().filter_map(|d| d.owner).filter_map(util::user_home).collect();
    homes.extend(util::user_home(util::uid()));
    homes.sort();
    homes.dedup();
    let mut n = 0;
    for h in homes {
        for sub in ["", "Downloads", "tmp", "src"] {
            let d = if sub.is_empty() { h.clone() } else { h.join(sub) };
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                let l = name.to_ascii_lowercase();
                if l.starts_with("irondivi") && (l.ends_with(".tar.gz") || l.ends_with(".tgz") || l.ends_with(".zip") || l.ends_with(".tar.xz")) {
                    n += 1;
                    let md = e.metadata().ok();
                    outln!(o, "{}  {}  {}", r.path_of(&e.path()), md.as_ref().map(|m| util::human(m.len())).unwrap_or_default(), md.map(|m| util::rfc3339(m.mtime())).unwrap_or_default());
                }
            }
        }
    }
    if n == 0 {
        outln!(o, "none");
    }
    if !LINUX {
        head(o, "Homebrew");
        cmd_block_t(o, "brew", &["info", "--json=v2", "irondivi"], 20, 64 << 10);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::redact::Known;

    fn red() -> Redactor {
        Redactor::new([7; 32], &Known::default())
    }

    #[test]
    fn elf_header_of_this_test_binary() {
        let me = std::env::current_exe().unwrap();
        let b = std::fs::read(me).unwrap();
        let i = bin_info(&b).expect("own binary parses");
        assert!(i.format.starts_with("ELF") || i.format.starts_with("Mach-O"));
        if i.format.starts_with("ELF") {
            assert!(i.build_id.is_some() || i.interp.is_some());
        }
    }

    #[test]
    fn secrets_masked_unknown_named() {
        let r = red();
        assert_eq!(render_value(&r, "rpcpassword", "hunter2").as_deref(), Some("<set>"));
        assert_eq!(render_value(&r, "rpcuser", "").as_deref(), Some("<unset>"));
        assert_eq!(render_value(&r, "electrumapikey", "x").as_deref(), Some("<set>"));
        assert_eq!(render_value(&r, "dbcache", "400").as_deref(), Some("400"));
        assert_eq!(render_value(&r, "frobnicate", "x"), None);
        let h = render_value(&r, "addnode", "node.example.org:52472").unwrap();
        assert!(h.starts_with("host-") && h.ends_with(":52472"), "{h}");
        assert_eq!(render_value(&r, "addnode", "1.2.3.4:52472").as_deref(), Some("1.2.3.4:52472"));
        assert!(render_value(&r, "wallet", "savings.dat").unwrap().starts_with("walletfile-"));
    }
}
