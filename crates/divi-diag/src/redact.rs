// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The part of §6.2 the collectors need at collection time: per-run salted
//! pseudonyms, known values, the pattern pass and path pseudonymisation.
//! The §6.3 scanner, the "Old-log lines" bucketing, preview and consent are
//! later steps of §10 and are not here; every byte the collectors write
//! still goes through [`Redactor::scrub`] before it reaches the folder.

use hmac::{Hmac, Mac};
use regex::{Captures, Regex};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Values known to be private on this machine (§6.2 step 1)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Known {
    pub hostnames: Vec<String>,
    pub users: Vec<String>,
    pub machine_ids: Vec<String>,
    pub ips: Vec<String>,
}

/// Names never matched free-standing in log text (§6.2 step 1)
const COMMON_NAMES: &[&str] = &[
    "root", "admin", "user", "ubuntu", "debian", "pi", "irondivi", "divi", "localhost",
];

/// Path components kept as they are: well-known system directories and
/// irondivi's own fixed names (§6.2 "Paths")
const KEEP_COMPONENTS: &[&str] = &[
    "", ".", "..", "bin", "sbin", "lib", "lib32", "lib64", "libexec", "usr", "etc", "var", "opt",
    "home", "Users", "root", "tmp", "proc", "sys", "dev", "run", "srv", "mnt", "media", "log",
    "local", "share", "cache", "spool", "crash", "lib", "state", "Library", "Application Support",
    "Logs", "Caches", "Preferences", "LaunchAgents", "LaunchDaemons", "DiagnosticReports",
    "Containers", "Volumes", "private", "System", "Applications", "shm", "mapper", "disk",
    "by-uuid", "by-id", "fs", "cgroup", "kernel", "self", "task", "fd", "fdinfo", "ns", "net",
    "system", "user", "init.d", "conf.d", "systemd", "docker", "containers", "volumes", "_data",
    "overlay2", "lxc", "pve", "snap", "flatpak", "x86_64-linux-gnu", "aarch64-linux-gnu",
    "arm-linux-gnueabihf", "ld-linux-x86-64.so.2", "ld-linux-aarch64.so.1", "libc.so.6", "musl",
    "nix", "store", "homebrew", "Cellar", "pid", "status", "stat", "cmdline", "environ", "exe",
    "cwd", "io", "maps", "smaps_rollup", "wchan", "stack", "syscall", "limits", "mountinfo",
    "journal", "messages", "kern.log", "syslog", "dmesg", "coredump", "abrt", "apport",
    "machine-id", "hostname", "hosts", "os-release", "passwd", "locks", "meminfo", "cpuinfo",
    "pressure", "memory", "cpu", "vm", "sysctl.d", "security", "user_beancounters", "irq",
    "block", "devices", "virtual", "class", "power_supply", "thermal", "kmsg", "console",
    "null", "zero", "urandom", "random", "pts", "tty", "ptmx", "mqueue", "hugepages",
    // irondivi's own names
    ".irondivi", "IronDivi", "irondivi", "irondivid", "irondivi-cli", "divi-swapd", "divi-swap",
    ".divi", "Divi", "testnet", "testnet3", "regtest", "privatedivi", "chainstate", "blocks",
    "index", "wallet", "wallets", "diag", "debug.log", "irondivi.conf", "irondivi.toml",
    "masternode.conf", "divi.conf", "runs.log", "crash.log", "events.log", "chain-events.log",
    "health.log", "rpc-methods.log", "rpc-methods-reserved.log", "rpc-aggregate.log",
    "rpc-aggregate-hourly.log", "startup", "incidents", "invalid", "rejected-tx", "bad-messages",
    "own-invalid", "irondivid.running", "running", "_unresolved", "snapshot-request", ".cookie",
    ".lock", "LOCK", "CURRENT", "IDENTITY", "LOG", "peers.dat", "banlist.dat", "mncache.dat",
    "mnpayments.dat", "fee_estimates.dat", "netfulfilled.dat", "sporks", "backups", "electrum",
    "webui", "swap", "swaps", "irondivi-diag", "irondivi-replay", "divi-electrum", "divi-webui",
    ".local", ".config", ".cache", "irondivi.service",
    "irondivid.service", "wallet.dat", "zmq", "certs", "tls", "txindex", ".dockerenv", ".containerenv", "swap.img", "swapfile",
    "nfsd", "snap", "core", "core18", "core20", "core22", "core24", "lxd", "snapd",
    // macOS APFS system volumes (`df` on any Mac)
    "Data", "Preboot", "VM", "Update", "xarts", "iSCPreboot", "Hardware", "Recovery",
    // fixed mount-point names the OS, systemd, Docker, snapd and LXD create
    // (Revision 16, §6.2 "Paths"); IDs below them stay pseudonymised
    "boot", "efi", "firmware", "lock", "credentials", "rpc_pipefs", "binfmt_misc", "netns",
    "ingress_sbox", "snapd", "lxd.mnt", "common", "mntns", "shmounts", "merged", "diff", "work",
    "mounts", "secrets", "plugins", "propagated-mount", "debug", "tracing", "config", "pstore",
    "bpf", "efivars", "fusectl", "nsfs", "Shared",
];

const KEEP_PREFIXES: &[&str] = &[
    "debug.log.", "LOG.old.", "MANIFEST-", "OPTIONS-", "irondivi-diag-", ".irondivi-diag-fsync-",
    "libc", "libm", "libpthread", "libdl", "librt",
    "libgcc", "libstdc++", "ld-",
];

pub struct Redactor {
    key: [u8; 32],
    known_re: Option<Regex>,
    known_kind: Vec<(String, &'static str)>,
    users: HashSet<String>,
    keep_comp: HashSet<&'static str>,
    re_pem: Regex,
    re_header: Regex,
    re_secret_kv: Regex,
    re_urluser: Regex,
    re_email: Regex,
    re_mac: Regex,
    re_ipv4: Regex,
    re_ipv6: Regex,
    re_hex64: Regex,
    re_hexpub: Regex,
    re_xkey: Regex,
    re_divi_addr: Regex,
    re_wif: Regex,
    re_bech32: Regex,
    re_b64: Regex,
    re_host: Regex,
    re_path: Regex,
    re_home: Regex,
    re_dev: Regex,
}

/// Dotted names under these suffixes are hostnames (§6.2 step 2); the
/// project's own seed and service names are kept
const SUFFIXES: &str = "com|net|org|de|uk|us|ca|fr|nl|ru|cn|jp|au|info|biz|xyz|app|cloud|local|lan|home|internal|domains|me|co|eu|ch|se|no|fi|pl|it|es|br|in|localdomain|arpa|tech|online|site|host";
const KEEP_HOSTS: &[&str] = &[
    "diviproject.org", "divi.domains", "irondivi.com", "github.com", "githubusercontent.com",
    "docker.io", "docker.com", "rust-lang.org", "crates.io",
];

impl Redactor {
    pub fn new(salt: [u8; 32], known: &Known) -> Self {
        let mut known_kind: Vec<(String, &'static str)> = Vec::new();
        let mut users = HashSet::new();
        let mut push = |v: &str, kind: &'static str| {
            let v = v.trim();
            // a host name is matched from 3 characters (`hp1`); the
            // pattern only matches it as a whole word
            let min = if kind == "host" { 3 } else { 4 };
            if v.len() >= min && !COMMON_NAMES.contains(&v) {
                known_kind.push((v.to_string(), kind));
            }
        };
        for h in &known.hostnames {
            push(h, "host");
        }
        for u in &known.users {
            push(u, "u");
            users.insert(u.clone());
        }
        for m in &known.machine_ids {
            push(m, "mid");
        }
        known_kind.sort_by_key(|k| std::cmp::Reverse(k.0.len()));
        known_kind.dedup_by(|a, b| a.0 == b.0);
        let known_re = if known_kind.is_empty() {
            None
        } else {
            let alts: Vec<String> = known_kind.iter().map(|(v, _)| regex::escape(v)).collect();
            Regex::new(&format!(r"(^|[^A-Za-z0-9_.-])({})($|[^A-Za-z0-9_-])", alts.join("|"))).ok()
        };
        let b58 = "[1-9A-HJ-NP-Za-km-z]";
        Redactor {
            key: salt,
            known_re,
            known_kind,
            users,
            keep_comp: KEEP_COMPONENTS.iter().copied().collect(),
            re_pem: Regex::new(r"-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(-----END [A-Z0-9 ]+-----|$)").unwrap(),
            re_header: Regex::new(r"(?i)\b(authorization|cookie|set-cookie|proxy-authorization)(\s*:\s*)[^\r\n]*").unwrap(),
            re_secret_kv: Regex::new(
                r#"(?i)([A-Za-z0-9_.-]*(?:pass|secret|token|key|auth|rpcuser|cookie|seed|mnemonic)[A-Za-z0-9_.-]*)("?\s*[=:]\s*"?)([^\s",}\]]+)"#,
            )
            .unwrap(),
            re_urluser: Regex::new(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@").unwrap(),
            re_email: Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap(),
            re_mac: Regex::new(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b").unwrap(),
            re_ipv4: Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b").unwrap(),
            re_ipv6: Regex::new(r"(?i)(^|[^0-9a-z:_])([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?:%[a-z0-9]+)?)").unwrap(),
            re_hex64: Regex::new(r"(blk:|sha256:)?\b([0-9a-fA-F]{64})\b").unwrap(),
            re_hexpub: Regex::new(r"\b(?:[0-9a-fA-F]{130}|[0-9a-fA-F]{66})\b").unwrap(),
            re_xkey: Regex::new(&format!(r"\b[xtyz](?:prv|pub){}{{100,}}\b", b58)).unwrap(),
            re_divi_addr: Regex::new(&format!(r"\b[DSy]{}{{33}}\b", b58)).unwrap(),
            re_wif: Regex::new(&format!(r"\b{}{{51,52}}\b", b58)).unwrap(),
            re_bech32: Regex::new(r"\b(?:bc|tb|ltc|tltc|bcrt)1[02-9ac-hj-np-z]{20,}\b").unwrap(),
            re_b64: Regex::new(r"[A-Za-z0-9+/]{60,}={0,2}").unwrap(),
            re_host: Regex::new(&format!(
                r"(?i)\b((?:[a-z0-9](?:[a-z0-9-]{{0,61}}[a-z0-9])?\.)+(?:{}))\b",
                SUFFIXES
            ))
            .unwrap(),
            // "Application Support" is the one well-known macOS directory with a space
            re_path: Regex::new(r#"(^|[\s='"(\[,<>|:])(/(?:Application Support|[^\s'"()\[\],;|<>])+)"#).unwrap(),
            re_home: Regex::new(r"(/home/|/Users/)([^/\s:'\x22]+)").unwrap(),
            re_dev: Regex::new(r"^(sd[a-z]+|hd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+|dm-|loop|md|nbd|zram|sr)\d*(p\d+)?$|^disk\d+(s\d+)*$").unwrap(),
        }
    }

    /// A fresh random salt; it lives only in memory (and in the pipe to the
    /// collectors), never in a file
    pub fn new_salt() -> [u8; 32] {
        use rand::RngCore;
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        s
    }

    /// `<kind>-<4 hex>`
    pub fn pseudonym(&self, kind: &str, value: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).expect("hmac key");
        mac.update(kind.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        let out = mac.finalize().into_bytes();
        format!("{}-{:02x}{:02x}", kind, out[0], out[1])
    }

    /// The known values the pattern pass matches, after the length and
    /// common-name rules (the §6.3 scanner searches for exactly these)
    pub fn known_values(&self) -> impl Iterator<Item = (&str, &'static str)> {
        self.known_kind.iter().map(|(v, k)| (v.as_str(), *k))
    }

    /// A user name in a position that says it is one (owner column, `User=`)
    pub fn user(&self, name: &str) -> String {
        if name == "root" || name.is_empty() || name.chars().all(|c| c.is_ascii_digit()) && name == "0" {
            return name.to_string();
        }
        self.pseudonym("u", name)
    }

    /// One path component: kept when well known, else a pseudonym
    fn component(&self, c: &str, parent: Option<&str>) -> String {
        // A user name under /home or /Users is masked even when it is a
        // common word that is kept elsewhere (§6.2 step 1)
        if matches!(parent, Some("home") | Some("Users")) && !c.is_empty() && c != "Shared" && !is_pseudonym(c) {
            return self.pseudonym("u", c);
        }
        if self.keep_comp.contains(c)
            || c.chars().all(|ch| ch.is_ascii_digit())
            || KEEP_PREFIXES.iter().any(|p| c.starts_with(p))
            // the plan's /var/tmp/irondivi-<uid>/ diag root
            || c.strip_prefix("irondivi-").is_some_and(|u| !u.is_empty() && u.bytes().all(|b| b.is_ascii_digit()))
            || self.re_dev.is_match(c)
            || is_rocksdb_file(c)
            || is_system_unit(c)
            || is_pseudonym(c)
        {
            return c.to_string();
        }
        // A user-chosen unit or scope name keeps its systemd suffix
        for suf in [".service", ".scope", ".slice", ".mount", ".socket", ".timer"] {
            if let Some(stem) = c.strip_suffix(suf) {
                return format!("{}{}", self.pseudonym("p", stem), suf);
            }
        }
        self.pseudonym("p", c)
    }

    /// A path with every component that is not well known pseudonymised
    /// (`/home/u-3c1a/.irondivi`)
    pub fn path(&self, p: &str) -> String {
        let mut out = String::with_capacity(p.len());
        let mut parent: Option<&str> = None;
        for (i, comp) in p.split('/').enumerate() {
            if i > 0 {
                out.push('/');
            }
            out.push_str(&self.component(comp, parent));
            parent = Some(comp);
        }
        out
    }

    pub fn path_of(&self, p: &std::path::Path) -> String {
        self.path(&crate::util::escape_bytes(std::os::unix::ffi::OsStrExt::as_bytes(p.as_os_str())))
    }

    fn ip4_class(&self, a: Ipv4Addr) -> Option<&'static str> {
        let o = a.octets();
        if a.is_unspecified() || a.is_broadcast() || a == Ipv4Addr::new(127, 0, 0, 1) {
            return None; // kept verbatim: says nothing about the user
        }
        Some(if a.is_loopback() {
            "loopback"
        } else if a.is_private() {
            "rfc1918"
        } else if o[0] == 100 && (o[1] & 0xc0) == 64 {
            "cgnat"
        } else if a.is_link_local() {
            "linklocal"
        } else if a.is_multicast() {
            "multicast"
        } else {
            "public4"
        })
    }

    fn ip6_class(&self, a: Ipv6Addr) -> Option<&'static str> {
        if a.is_unspecified() || a.is_loopback() {
            return None;
        }
        let s = a.segments();
        Some(if (s[0] & 0xffc0) == 0xfe80 {
            "linklocal6"
        } else if (s[0] & 0xfe00) == 0xfc00 {
            "ula"
        } else if (s[0] & 0xff00) == 0xff00 {
            "multicast6"
        } else if let Some(v4) = a.to_ipv4_mapped() {
            return self.ip4_class(v4);
        } else {
            "public6"
        })
    }

    /// The whole §6.2 pass this step implements, over one block of text
    pub fn scrub(&self, text: &str) -> String {
        let t = self.re_pem.replace_all(text, "<pem block removed>");
        let t = self.re_header.replace_all(&t, "$1$2<set>");
        let t = self.re_urluser.replace_all(&t, "$1<set>@");
        let t = self.re_secret_kv.replace_all(&t, |c: &Captures| {
            let v = &c[3];
            // `<set>`/`<unset>` and pseudonyms written by a collector stay
            if v.starts_with('<') || v == "yes" || v == "no" {
                c[0].to_string()
            } else {
                format!("{}{}<set>", &c[1], &c[2])
            }
        });
        let t = self.re_email.replace_all(&t, "<email>");
        let t = self.re_xkey.replace_all(&t, "<xkey>");
        let t = self.re_hexpub.replace_all(&t, "<pubkey-hex>");
        let t = self.re_hex64.replace_all(&t, |c: &Captures| {
            if c.get(1).is_some() {
                c[0].to_string()
            } else {
                self.pseudonym("h64", &c[2].to_ascii_lowercase())
            }
        });
        let t = self.re_wif.replace_all(&t, "<wif>");
        let t = self.re_divi_addr.replace_all(&t, |c: &Captures| {
            let s = &c[0];
            // a base58 address has digits and both cases
            if s.chars().any(|ch| ch.is_ascii_digit()) && s.chars().any(|ch| ch.is_ascii_lowercase()) {
                "<addr>".to_string()
            } else {
                s.to_string()
            }
        });
        let t = self.re_bech32.replace_all(&t, "<addr>");
        // a 64-hex value that survived the step above was marked public
        let t = self.re_b64.replace_all(&t, |c: &Captures| {
            let s = &c[0];
            if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
                s.to_string()
            } else {
                "<base64>".to_string()
            }
        });
        let t = self.re_mac.replace_all(&t, "<mac>");
        let t = self.re_ipv4.replace_all(&t, |c: &Captures| {
            let parts: Vec<u32> = (1..=4).map(|i| c[i].parse().unwrap_or(999)).collect();
            if parts.iter().any(|&p| p > 255) {
                return c[0].to_string();
            }
            let a = Ipv4Addr::new(parts[0] as u8, parts[1] as u8, parts[2] as u8, parts[3] as u8);
            match self.ip4_class(a) {
                None => c[0].to_string(),
                Some(k) => self.pseudonym(k, &c[0]),
            }
        });
        let t = self.re_ipv6.replace_all(&t, |c: &Captures| {
            let cand = &c[2];
            let addr = cand.split('%').next().unwrap_or("");
            let colons = addr.matches(':').count();
            if !(addr.contains("::") || colons == 7) || addr.len() < 3 {
                return c[0].to_string();
            }
            match addr.parse::<Ipv6Addr>() {
                Ok(a) => match self.ip6_class(a) {
                    None => c[0].to_string(),
                    Some(k) => format!("{}{}", &c[1], self.pseudonym(k, addr)),
                },
                Err(_) => c[0].to_string(),
            }
        });
        let t = self.re_host.replace_all(&t, |c: &Captures| {
            let h = c[1].to_ascii_lowercase();
            if KEEP_HOSTS.iter().any(|k| h == *k || h.ends_with(&format!(".{}", k))) {
                c[0].to_string()
            } else {
                self.pseudonym("host", &h)
            }
        });
        let t = self.re_path.replace_all(&t, |c: &Captures| {
            // "/proc/cpuinfo:" — trailing punctuation is not part of the name
            let whole = &c[2];
            // "scheme://host/..." is a URL: its host was handled above
            if &c[1] == ":" && whole.starts_with("//") {
                return c[0].to_string();
            }
            let body = whole.trim_end_matches([':', '.', ',']);
            let body = if body.is_empty() { whole } else { body };
            format!("{}{}{}", &c[1], self.path(body), &whole[body.len()..])
        });
        let t = self.re_home.replace_all(&t, |c: &Captures| {
            let name = &c[2];
            if name.starts_with("u-") && name.len() == 6 {
                c[0].to_string()
            } else {
                format!("{}{}", &c[1], self.pseudonym("u", name))
            }
        });
        let t = match &self.known_re {
            None => t,
            Some(re) => re.replace_all(&t, |c: &Captures| {
                let v = &c[2];
                let kind = self
                    .known_kind
                    .iter()
                    .find(|(k, _)| k == v)
                    .map(|(_, k)| *k)
                    .unwrap_or("p");
                format!("{}{}{}", &c[1], self.pseudonym(kind, v), &c[3])
            }),
        };
        t.into_owned()
    }

    /// Is this one of the machine's non-system users?
    pub fn is_known_user(&self, name: &str) -> bool {
        self.users.contains(name)
    }
}

/// A component that is already a pseudonym (a collector redacted it before
/// the parent's scrub saw it again)
fn is_pseudonym(c: &str) -> bool {
    let stem = c
        .strip_suffix(".service")
        .or_else(|| c.strip_suffix(".scope"))
        .or_else(|| c.strip_suffix(".slice"))
        .unwrap_or(c);
    let Some((kind, hex)) = stem.rsplit_once('-') else { return false };
    let hex_ok = hex.len() == 4 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    hex_ok
        && matches!(
            kind,
            "u" | "p" | "host" | "h64" | "mid" | "rfc1918" | "public4" | "cgnat" | "linklocal" | "loopback"
                | "multicast" | "ula" | "linklocal6" | "public6" | "multicast6"
        )
}

fn is_rocksdb_file(c: &str) -> bool {
    let stem = c.split('.').next().unwrap_or("");
    (stem.len() >= 6 && stem.chars().all(|ch| ch.is_ascii_digit()))
        && (c.ends_with(".sst") || c.ends_with(".log") || c.ends_with(".ldb") || c.ends_with(".blob"))
}

fn is_system_unit(c: &str) -> bool {
    let systemd_prefix = [
        "system", "user", "init", "machine", "session-", "user-", "user@", "docker", "libpod",
        "lxc", "systemd-", "irondivi", "containerd", "crio", "kubepods", "cri-containerd",
        "-.slice", "dbus", "ssh", "cron", "getty", "snapd", "polkit", "networkd", "resolved",
        "journald", "udev", "logind", "chrony", "ntp", "rsyslog", "app.slice", "background.slice",
        "lxcfs", "pve", "accounts-daemon", "multipathd", "tailscaled", "unattended-upgrades",
    ];
    let is_unit = [".service", ".scope", ".slice", ".mount", ".socket", ".timer"]
        .iter()
        .any(|s| c.ends_with(s));
    is_unit && systemd_prefix.iter().any(|p| c.starts_with(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r() -> Redactor {
        Redactor::new(
            [7u8; 32],
            &Known {
                hostnames: vec!["myhostname".into(), "myhostname.example.lan".into()],
                users: vec!["alice".into(), "pi".into()],
                machine_ids: vec!["0123456789abcdef0123456789abcdef".into()],
                ips: vec![],
            },
        )
    }

    #[test]
    fn paths_are_pseudonymised() {
        let r = r();
        let p = r.path("/home/alice/.irondivi/debug.log");
        assert!(p.starts_with("/home/u-") && p.ends_with("/.irondivi/debug.log"), "{p}");
        let p = r.path("/opt/divimarket/bin/divid");
        assert!(!p.contains("divimarket"), "{p}");
        assert_eq!(r.path("/proc/123/status"), "/proc/123/status");
        assert_eq!(r.path("/dev/sda1"), "/dev/sda1");
        assert_eq!(r.path("/dev/disk3s1s1"), "/dev/disk3s1s1");
        assert_eq!(r.path("/System/Volumes/Preboot"), "/System/Volumes/Preboot");
        assert_eq!(r.path("/system.slice/irondivid.service"), "/system.slice/irondivid.service");
        // fixed mount-point names stay readable; IDs and user-chosen names do not
        for keep in ["/boot", "/boot/efi", "/run/lock", "/run/rpc_pipefs", "/run/snapd/ns/lxd.mnt",
            "/var/snap/lxd/common/ns/shmounts", "/run/credentials/systemd-sysusers.service",
            "/sys/kernel/debug", "/sys/firmware/efi/efivars", "/run/docker/netns/ingress_sbox"] {
            assert_eq!(r.path(keep), keep);
        }
        let h = "8a3f".repeat(16);
        for (p, tail) in [(format!("/var/lib/docker/overlay2/{h}/merged"), "/merged"),
            (format!("/var/lib/docker/containers/{h}/mounts/secrets"), "/mounts/secrets"),
            (format!("/var/lib/docker/plugins/{h}/propagated-mount"), "/propagated-mount")] {
            let got = r.path(&p);
            assert!(!got.contains(&h) && got.ends_with(tail), "{got}");
        }
        for u in ["user", "debug", "work", "ubuntu"] {
            assert!(r.path(&format!("/home/{u}/.irondivi")).starts_with("/home/u-"), "{u}");
        }
        assert_eq!(r.path("/Users/Shared"), "/Users/Shared");
        for p in ["/dev/mapper/vgdata-lvchain", "/mnt/mydisk", "/run/docker/netns/07b2aa7135fd"] {
            let got = r.path(p);
            assert!(!got.contains("vgdata") && !got.contains("mydisk") && !got.contains("07b2aa"), "{got}");
        }
        let cg = "/user.slice/user-1000.slice/session-2.scope";
        assert_eq!(r.scrub(&format!("  {cg} memory.max=max")), format!("  {cg} memory.max=max"));
        assert_eq!(r.scrub("CPUs in /proc/cpuinfo: 32"), "CPUs in /proc/cpuinfo: 32");
        assert_eq!(r.scrub("/root/.dockerenv absent"), "/root/.dockerenv absent");
        let mac = "/Users/x/Library/Application Support/IronDivi";
        assert!(r.scrub(mac).ends_with("/Library/Application Support/IronDivi"), "{}", r.scrub(mac));
        assert_eq!(r.scrub("at /home/u-1a2b/.irondivi/txindex"), "at /home/u-1a2b/.irondivi/txindex");
        // rocksdb writes "manifest file:/home/..." with no space before the path
        let m = r.scrub("Recovered from manifest file:/home/alice/mynode/txindex/MANIFEST-000001 ok");
        assert!(!m.contains("alice") && !m.contains("mynode") && m.contains("/txindex/MANIFEST-000001"), "{m}");
        assert!(r.scrub("url http://127.0.0.1:8480/healthz").contains("http://127.0.0.1:8480/healthz"));
    }

    #[test]
    fn user_chosen_irondivi_names_are_pseudonymised() {
        // a folder the user named irondivi-<something> is user data (Revision 16)
        let r = r();
        for (p, gone) in [
            ("/srv/irondivi-aliceshop/debug.log", "aliceshop"),
            ("/data/irondivid-mainbox/blocks", "mainbox"),
            ("/mnt/divi-secretvault/wallet.dat", "secretvault"),
        ] {
            let s = r.path(p);
            assert!(!s.contains(gone), "{p} -> {s}");
        }
        // the plan's own names stay
        assert_eq!(r.path("/var/tmp/irondivi-1000/diag"), "/var/tmp/irondivi-1000/diag");
        assert_eq!(r.path("/usr/local/bin/irondivi-cli"), "/usr/local/bin/irondivi-cli");
        assert_eq!(r.path("/usr/local/bin/irondivi-replay"), "/usr/local/bin/irondivi-replay");
        let d = r.path("/var/tmp/irondivi-diag-20261031-1200");
        assert_eq!(d, "/var/tmp/irondivi-diag-20261031-1200");
    }

    #[test]
    fn scrub_masks_private_values() {
        let r = r();
        let s = r.scrub(
            "host myhostname ip 192.168.1.20 pub 8.8.8.8 lo 127.0.0.1 mac aa:bb:cc:dd:ee:ff \
             rpcpassword=hunter2 me@x.com /home/pi/x user alice id 0123456789abcdef0123456789abcdef \
             v6 2001:db8::1 at 2026-10-30T12:34:56Z mod divi_node::staker",
        );
        for bad in ["myhostname", "192.168", "8.8.8.8", "aa:bb", "hunter2", "me@x.com", "/home/pi", "alice", "0123456789abcdef", "2001:db8"] {
            assert!(!s.contains(bad), "{bad} left in {s}");
        }
        assert!(s.contains("127.0.0.1"));
        assert!(s.contains("12:34:56"), "{s}");
        assert!(s.contains("divi_node::staker"), "{s}");
        assert!(s.contains("rpcpassword=<set>"));
    }

    #[test]
    fn same_value_same_pseudonym() {
        let r = r();
        assert_eq!(r.pseudonym("u", "bob"), r.pseudonym("u", "bob"));
        assert_ne!(r.pseudonym("u", "bob"), r.pseudonym("u", "bo"));
    }

    #[test]
    fn hashes_marked_public_stay() {
        let r = r();
        let h = "a".repeat(64);
        assert!(r.scrub(&format!("sha256:{h}")).contains(&h));
        assert!(!r.scrub(&format!("tx {h}")).contains(&h));
    }
}
