// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! B4 platform backends: what differs by platform beyond the B2 default.
//! B4.1 (libc, BusyBox, Alpine/OpenRC), B4.2 (macOS: Rosetta and TCC; the
//! rest of B4.2 is in the B2 collectors), B4.3 (Raspberry Pi and other ARM
//! boards), B4.4 (WSL 1 and 2) and B4.5 (Docker Desktop; the other
//! container kinds are B2.3).
//!
//! The parsers are plain functions over text so the tests can feed them
//! fixtures from hosts we do not have.

use super::{files, head, logs, one, storage, LINUX};
use crate::ctx::Ctx;
use crate::frame::Out;
use crate::outln;
use crate::util;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn platform(ctx: &Ctx, o: &mut Out) {
    o.file("host/platform.txt");
    if LINUX {
        linux(ctx, o);
    } else {
        macos(ctx, o);
    }
    docker_desktop(ctx, o);
}

/// The node binaries worth looking at: the running nodes' executables,
/// then the copies B1.2 finds
fn binaries(ctx: &Ctx) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = ctx.nodes.iter().filter_map(|n| n.exe.clone()).collect();
    for (p, _) in files::copies(ctx) {
        if !v.contains(&p) {
            v.push(p);
        }
    }
    v.truncate(8);
    v
}

fn header(p: &Path) -> Option<files::BinInfo> {
    files::bin_info(&util::read_bytes_capped(p, 1 << 16).ok()?)
}

// ---------------------------------------------------------------- B4.1

/// glibc, musl or static, from an ELF interpreter path
pub fn libc_kind(interp: Option<&str>) -> &'static str {
    match interp {
        None => "static (no interpreter)",
        Some(i) if i.contains("ld-musl") => "musl",
        Some(i) if i.contains("ld-linux") || i.contains("ld64.so") || i.contains("ld.so") => "glibc",
        Some(_) => "unknown interpreter",
    }
}

/// True when `target` (a resolved tool path) is BusyBox
pub fn is_busybox(target: &Path) -> bool {
    target.file_name().and_then(|n| n.to_str()).is_some_and(|n| n == "busybox" || n.starts_with("busybox."))
}

fn linux(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    head(o, "B4.1 C library");
    let mut list: Vec<PathBuf> = std::env::current_exe().ok().into_iter().collect();
    for p in binaries(ctx) {
        if !list.contains(&p) {
            list.push(p);
        }
    }
    for p in list {
        let shown = r.path_of(&p);
        match header(&p) {
            Some(i) => outln!(o, "{shown}: {}, {}, {}", i.format, i.machine, libc_kind(i.interp.as_deref())),
            None => outln!(o, "{shown}: header not readable"),
        }
    }
    let musl_host = std::fs::read_dir("/lib").map(|d| d.flatten().any(|e| e.file_name().to_string_lossy().starts_with("ld-musl"))).unwrap_or(false);
    outln!(o, "host loader: {}", if musl_host { "musl (/lib/ld-musl-*)" } else { "no musl loader in /lib" });
    if Path::new("/etc/alpine-release").exists() {
        outln!(o, "Alpine {}; services are OpenRC (`rc-service`, B2.5) and the system log is /var/log/messages or `logread` (B2.11)", one("/etc/alpine-release"));
    }

    head(o, "B4.1 BusyBox");
    let mut bb = Vec::new();
    for t in ["ps", "dmesg", "df", "free", "top", "ip", "netstat", "ss", "mount", "sh"] {
        if let Some(p) = util::which(t) {
            if is_busybox(&p.canonicalize().unwrap_or(p)) {
                bb.push(t);
            }
        }
    }
    if bb.is_empty() {
        outln!(o, "no BusyBox applets among the tools diag uses");
    } else {
        outln!(o, "BusyBox applets: {} (their shorter output is accepted as it is)", bb.join(" "));
    }

    wsl(ctx, o);
    if cfg!(any(target_arch = "arm", target_arch = "aarch64")) || machine_is_arm() {
        arm(ctx, o);
    }
}

fn machine_is_arm() -> bool {
    let m = util::cmd("uname", &["-m"]).text();
    let m = m.trim();
    m.starts_with("arm") || m == "aarch64"
}

// ---------------------------------------------------------------- B4.4

/// WSL 1 or 2 from `/proc/version` and `/proc/sys/kernel/osrelease`;
/// `None` when not WSL
pub fn wsl_version(proc_version: &str, osrelease: &str) -> Option<u8> {
    let v = proc_version.to_ascii_lowercase();
    let r = osrelease.to_ascii_lowercase();
    if r.contains("wsl2") || r.contains("microsoft-standard") {
        return Some(2);
    }
    // WSL 1 reports a fake kernel string such as 4.4.0-19041-Microsoft
    if r.ends_with("-microsoft") || v.contains("microsoft") {
        return Some(1);
    }
    None
}

/// A WSL distro name shown as it is when it is one the Store ships, else
/// "(a custom name)": the name may be the user's own choice
pub fn wsl_distro_shown(name: &str) -> String {
    const STOCK: &[&str] = &[
        "Ubuntu", "Debian", "kali-linux", "openSUSE", "SUSE", "SLES", "OracleLinux", "AlmaLinux", "Alpine",
        "Fedora", "archlinux", "docker-desktop", "docker-desktop-data", "Pengwin", "FedoraRemix",
    ];
    let stock = STOCK.iter().any(|s| name == *s || name.strip_prefix(s).is_some_and(|rest| rest.starts_with('-') && rest[1..].chars().all(|c| c.is_ascii_digit() || c == '.')));
    if stock {
        name.to_string()
    } else {
        "(a custom name)".into()
    }
}

/// A mount that is a Windows drive seen from WSL (`drvfs`, or 9p from a
/// drive letter under /mnt)
pub fn is_drvfs(fstype: &str, source: &str, point: &str) -> bool {
    if fstype == "drvfs" {
        return true;
    }
    let drive = point.strip_prefix("/mnt/").is_some_and(|d| d.len() == 1 && d.chars().all(|c| c.is_ascii_alphabetic()));
    fstype == "9p" && (drive || source.contains(":\\") || source == "drvfs" || source.ends_with(':'))
}

pub const WSL_L3: &[&str] = &[
    "wsl --status",
    "Get-Content $env:USERPROFILE\\.wslconfig",
    "Get-WinEvent -FilterHashtable @{LogName='System'; StartTime=(Get-Date).AddDays(-7)} | Where-Object { $_.ProviderName -match 'Hyper-V|vmcompute|Lxss|Resource-Exhaustion' }",
];

fn wsl(ctx: &Ctx, o: &mut Out) {
    let pv = util::read_small(Path::new("/proc/version"), 4096).unwrap_or_default();
    let rel = util::read_small(Path::new("/proc/sys/kernel/osrelease"), 4096).unwrap_or_default();
    let Some(ver) = wsl_version(&pv, rel.trim()) else { return };
    let r = ctx.redactor();
    head(o, "B4.4 WSL");
    outln!(o, "WSL {ver} (from /proc/sys/kernel/osrelease and /proc/version)");
    match std::env::var("WSL_DISTRO_NAME") {
        Ok(n) => outln!(o, "distro: {}", wsl_distro_shown(&n)),
        Err(_) => outln!(o, "distro: WSL_DISTRO_NAME not set"),
    }
    if ver == 1 {
        outln!(o, "WSL 1 has no real cgroups and gives no fdatasync guarantee: a power loss or a Windows crash can damage the chain database");
    }
    let ms = storage::mounts();
    for d in &ctx.datadirs {
        if let Some(m) = storage::mount_of(&ms, &d.path) {
            if is_drvfs(&m.fstype, &m.source, &m.point) {
                outln!(o, "datadir-{} is on a Windows drive ({} at {}): slow, and unsafe for RocksDB; move it under the Linux home (~)", d.n, m.fstype, r.path(&m.point));
            } else {
                outln!(o, "datadir-{} is on {} (a Linux filesystem)", d.n, m.fstype);
            }
        }
    }
    outln!(o, "The Windows side (memory limit in .wslconfig, Hyper-V events) cannot be read from inside WSL.");
    outln!(o, "§7.2 L3, in PowerShell on Windows:");
    for c in WSL_L3 {
        outln!(o, "  {c}");
    }
}

// ---------------------------------------------------------------- B4.3

/// `vcgencmd get_throttled` (`throttled=0x50005`) or the firmware sysfs
/// file (`50005`, hex without a prefix)
pub fn parse_throttled(s: &str) -> Option<u32> {
    let v = s.trim();
    let v = v.strip_prefix("throttled=").unwrap_or(v);
    let v = v.strip_prefix("0x").unwrap_or(v);
    u32::from_str_radix(v, 16).ok()
}

/// The get_throttled bits, now and since boot
pub fn decode_throttled(bits: u32) -> Vec<&'static str> {
    const B: &[(u32, &str)] = &[
        (0, "under-voltage now"),
        (1, "ARM frequency capped now"),
        (2, "throttled now"),
        (3, "soft temperature limit now"),
        (16, "under-voltage has occurred since boot"),
        (17, "ARM frequency capping has occurred since boot"),
        (18, "throttling has occurred since boot"),
        (19, "soft temperature limit has occurred since boot"),
    ];
    B.iter().filter(|(b, _)| bits & (1 << b) != 0).map(|(_, s)| *s).collect()
}

/// `mmcN:` lines in the kernel log that report an error
pub fn mmc_errors(dmesg: &str) -> Vec<String> {
    dmesg
        .lines()
        .filter(|l| {
            let lo = l.to_ascii_lowercase();
            let mmc = lo.contains("mmc0") || lo.contains("mmc1") || lo.contains("mmcblk");
            mmc && ["error", "timeout", "timed out", "crc", "-110", "-84", "i/o error", "reset"].iter().any(|k| lo.contains(k))
        })
        .map(|l| l.trim().to_string())
        .collect()
}

/// A swap device or file that lives on an SD card
pub fn swap_on_sd(swaps: &str, mounts: &[storage::Mount]) -> Vec<String> {
    let mut v = Vec::new();
    for l in swaps.lines().skip(1) {
        let mut f = l.split_whitespace();
        let (Some(dev), kind) = (f.next(), f.next()) else { continue };
        // a swap file sits on whatever filesystem holds it; a partition is itself
        let on_sd = dev.contains("mmcblk")
            || kind == Some("file")
                && mounts.iter().filter(|m| dev.starts_with(&m.point)).max_by_key(|m| m.point.len()).is_some_and(|m| m.source.contains("mmcblk"));
        if on_sd {
            v.push(dev.to_string());
        }
    }
    v
}

fn arm(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    head(o, "B4.3 ARM board");
    outln!(o, "model: {}", one("/proc/device-tree/model").trim_end_matches('\0'));
    let init = Path::new("/sbin/init").canonicalize().unwrap_or_else(|_| "/sbin/init".into());
    let init_fmt = header(&init).map(|i| i.format);
    outln!(o, "/sbin/init: {}", init_fmt.as_deref().unwrap_or("header not readable"));
    let mut node32 = false;
    for p in binaries(ctx) {
        if let Some(i) = header(&p) {
            node32 |= i.format.starts_with("ELF 32");
            let note = match &init_fmt {
                Some(f) if f.split(' ').nth(1) != i.format.split(' ').nth(1) => "  <- differs from /sbin/init (64-bit kernel with 32-bit userland, or the reverse)",
                _ => "",
            };
            outln!(o, "{}: {}, {}{note}", r.path_of(&p), i.format, i.machine);
        }
    }

    // under-voltage: vcgencmd, then the firmware file, then hwmon
    let mut source = None;
    let v = util::run_cmd("vcgencmd", &["get_throttled"], Duration::from_secs(5), 4096);
    if let Some(b) = v.ok().then(|| parse_throttled(&v.text())).flatten() {
        source = Some(("vcgencmd get_throttled", b));
    } else if let Some(b) = util::read_small(Path::new("/sys/devices/platform/soc/soc:firmware/get_throttled"), 64).and_then(|s| parse_throttled(&s)) {
        source = Some(("/sys/devices/platform/soc/soc:firmware/get_throttled", b));
    }
    match source {
        Some((src, b)) => {
            let d = decode_throttled(b);
            outln!(o, "throttling ({src}): {:#x} {}", b, if d.is_empty() { "none".to_string() } else { d.join("; ") });
        }
        None => {
            let alarms: Vec<String> = std::fs::read_dir("/sys/class/hwmon")
                .map(|rd| rd.flatten().filter_map(|e| util::read_small(&e.path().join("in0_lcrit_alarm"), 16).map(|v| format!("{}={}", e.file_name().to_string_lossy(), v.trim()))).collect())
                .unwrap_or_default();
            if alarms.is_empty() {
                outln!(o, "throttling: no under-voltage source on this board (vcgencmd {}, no firmware file, no hwmon in0_lcrit_alarm)", if v.spawn_error.is_some() { "missing" } else { "could not answer (no /dev/vchiq access?)" });
            } else {
                outln!(o, "throttling (hwmon in0_lcrit_alarm, 1 = under-voltage): {}", alarms.join(" "));
            }
        }
    }

    if let Ok(rd) = std::fs::read_dir("/sys/class/thermal") {
        let mut zones: Vec<PathBuf> = rd.flatten().map(|e| e.path()).filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("thermal_zone"))).collect();
        zones.sort();
        for z in zones {
            let t = one(&z.join("temp").to_string_lossy());
            let c = t.parse::<i64>().map(|m| format!("{:.1} °C", m as f64 / 1000.0)).unwrap_or(t);
            outln!(o, "{}: {} {c}", z.file_name().unwrap_or_default().to_string_lossy(), one(&z.join("type").to_string_lossy()));
        }
    }

    let dm = util::run_cmd("dmesg", &[], Duration::from_secs(10), 8 << 20);
    if dm.ok() {
        let e = mmc_errors(&dm.text());
        outln!(o, "SD/MMC errors in the kernel log: {}", e.len());
        for l in e.iter().rev().take(20).rev() {
            outln!(o, "  {l}");
        }
    } else {
        outln!(o, "SD/MMC errors: dmesg not readable ({})", dm.status_line());
    }
    // the card's CID: name, maker and date; never the serial
    let cid = Path::new("/sys/block/mmcblk0/device");
    if cid.exists() {
        let f = |k: &str| one(&cid.join(k).to_string_lossy());
        outln!(o, "SD card: type {} name {} manfid {} oemid {} date {}", f("type"), f("name"), f("manfid"), f("oemid"), f("date"));
    }
    if cfg!(target_pointer_width = "32") || node32 {
        for n in &ctx.nodes {
            let v = super::status_fields(&n.pid.to_string(), &["VmPeak", "VmSize"]);
            outln!(o, "32-bit node pid {}: {} (the address space ends near 3 GB)", n.pid, if v.is_empty() { "status not readable".into() } else { v.join(", ") });
        }
    }
    let sw = util::read_small(Path::new("/proc/swaps"), 64 << 10).unwrap_or_default();
    for s in swap_on_sd(&sw, &storage::mounts()) {
        outln!(o, "warning: swap {} is on the SD card: slow, and it wears the card out", r.path(&s));
    }
}

// ---------------------------------------------------------------- B4.5

/// Docker Desktop's hidden VM, from the kernel release or `docker info`
pub fn is_docker_desktop(kernel_release: &str, docker_info: &str) -> bool {
    kernel_release.contains("linuxkit") || docker_info.lines().any(|l| l.trim().starts_with("Operating System:") && l.contains("Docker Desktop"))
}

pub const DOCKER_DESKTOP_L3: &[&str] =
    &["docker run --rm --privileged --pid=host alpine dmesg > dd-dmesg.txt", "docker info > dd-info.txt"];

fn docker_desktop(_ctx: &Ctx, o: &mut Out) {
    let rel = if LINUX { util::read_small(Path::new("/proc/sys/kernel/osrelease"), 4096).unwrap_or_default() } else { String::new() };
    let info = if util::which("docker").is_some() {
        util::run_cmd("docker", &["info", "--format", "Operating System: {{.OperatingSystem}}"], Duration::from_secs(10), 64 << 10).text()
    } else {
        String::new()
    };
    if !is_docker_desktop(&rel, &info) {
        return;
    }
    head(o, "B4.5 Docker Desktop");
    outln!(o, "Docker Desktop: the Docker host is a hidden VM, so its kernel log and memory are not visible here.");
    outln!(o, "§7.2 L3, on the machine that runs Docker Desktop (the first pulls the alpine image from Docker Hub):");
    for c in DOCKER_DESKTOP_L3 {
        outln!(o, "  {c}");
    }
}

// ---------------------------------------------------------------- B4.2

/// The TCC-protected area a path is in, relative to the user's home
pub fn tcc_area(p: &Path, home: &Path) -> Option<&'static str> {
    if p.starts_with("/Volumes") {
        return Some("removable or network volume");
    }
    let rel = p.strip_prefix(home).ok()?;
    let first = rel.components().next()?.as_os_str().to_str()?;
    match first {
        "Desktop" => Some("Desktop"),
        "Documents" => Some("Documents"),
        "Downloads" => Some("Downloads"),
        "Library" => {
            // Application Support/IronDivi is the default data dir and is not
            // protected; the TCC-guarded Library subtrees are
            let second = rel.components().nth(1).and_then(|c| c.as_os_str().to_str()).unwrap_or("");
            ["Mail", "Messages", "Safari", "Containers", "Group Containers", "Mobile Documents", "CloudStorage", "Calendars", "Cookies"]
                .contains(&second)
                .then_some("~/Library (protected subtree)")
        }
        _ => None,
    }
}

pub const TCC_STEP: &str = "System Settings → Privacy & Security → Full Disk Access → add the terminal app, then re-run";

/// A line of the node's own log that is a TCC refusal: "Operation not
/// permitted" (EPERM) on a path in a protected area
pub fn tcc_log_line(l: &str, home: &Path) -> Option<&'static str> {
    if !(l.contains("Operation not permitted") || l.contains("os error 1)")) {
        return None;
    }
    l.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ':')
        .filter(|w| w.starts_with('/'))
        .find_map(|w| tcc_area(Path::new(w), home))
}

fn macos(ctx: &Ctx, o: &mut Out) {
    let r = ctx.redactor();
    head(o, "B4.2 Rosetta");
    let arm_host = util::cmd("sysctl", &["-n", "hw.optional.arm64"]).text().trim() == "1";
    let translated = util::cmd("sysctl", &["-n", "sysctl.proc_translated"]).text().trim() == "1";
    outln!(o, "host: {}; diag itself {}", if arm_host { "Apple silicon" } else { "Intel" }, if translated { "runs under Rosetta" } else { "runs natively" });
    for p in binaries(ctx) {
        if let Some(i) = header(&p) {
            let rosetta = arm_host && !i.machine.contains("arm64") && i.machine.contains("x86_64");
            outln!(o, "{}: {} {}{}", r.path_of(&p), i.format, i.machine, if rosetta { " — runs under Rosetta translation on this Mac" } else { "" });
        }
    }

    head(o, "B4.2 macOS privacy (TCC)");
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
    let mut blocked = 0;
    let mut paths: Vec<PathBuf> = ctx.datadirs.iter().map(|d| d.path.clone()).collect();
    paths.extend(ctx.datadirs.iter().filter_map(|d| d.conf.clone()));
    paths.extend(ctx.nodes.iter().filter_map(|n| n.datadir.clone()));
    for p in paths {
        let e = if p.is_dir() { std::fs::read_dir(&p).err() } else { std::fs::File::open(&p).err() };
        if let Some(e) = e {
            if e.raw_os_error() == Some(libc::EPERM) {
                if let Some(a) = tcc_area(&p, &home) {
                    blocked += 1;
                    outln!(o, "{}: blocked by macOS privacy (TCC), {a}; not a missing file. {TCC_STEP}", r.path_of(&p));
                }
            }
        }
    }
    // the node's own errors (runs.log and debug.log)
    for d in &ctx.datadirs {
        let mut files = logs::debug_logs(d);
        files.extend(logs::find_diag_file(d, "runs.log"));
        for f in files.iter().rev().take(3) {
            let Some(t) = util::read_small(f, 8 << 20) else { continue };
            for l in t.lines().rev().take(20000) {
                if let Some(a) = tcc_log_line(l, &home) {
                    blocked += 1;
                    outln!(o, "datadir-{} node log: a path in {a} was refused by macOS privacy (TCC). {TCC_STEP}", d.n);
                    break;
                }
            }
        }
    }
    if blocked == 0 {
        outln!(o, "no path diag or the node needs was refused by TCC");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn libc_from_interp() {
        assert_eq!(libc_kind(Some("/lib/ld-musl-x86_64.so.1")), "musl");
        assert_eq!(libc_kind(Some("/lib64/ld-linux-x86-64.so.2")), "glibc");
        assert_eq!(libc_kind(Some("/lib/ld-linux-armhf.so.3")), "glibc");
        assert_eq!(libc_kind(None), "static (no interpreter)");
        assert!(is_busybox(Path::new("/bin/busybox")));
        assert!(!is_busybox(Path::new("/usr/bin/ps")));
    }

    #[test]
    fn wsl_detection() {
        // WSL 2 (fixtures from Ubuntu 22.04 on Windows 11)
        assert_eq!(wsl_version("Linux version 5.15.153.1-microsoft-standard-WSL2 (root@941d701f84f1) ...", "5.15.153.1-microsoft-standard-WSL2"), Some(2));
        // WSL 1 (Windows 10 19045)
        assert_eq!(wsl_version("Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com) (gcc version 5.4.0 (GCC) )", "4.4.0-19041-Microsoft"), Some(1));
        assert_eq!(wsl_version("Linux version 6.8.0-49-generic (buildd@lcy02-amd64-103)", "6.8.0-49-generic"), None);
        assert_eq!(wsl_distro_shown("Ubuntu-22.04"), "Ubuntu-22.04");
        assert_eq!(wsl_distro_shown("Debian"), "Debian");
        assert_eq!(wsl_distro_shown("alices-node"), "(a custom name)");
        assert_eq!(wsl_distro_shown("Ubuntu-alice"), "(a custom name)");
        assert!(is_drvfs("9p", "C:\\", "/mnt/c"));
        assert!(is_drvfs("9p", "drvfs", "/mnt/d"));
        assert!(is_drvfs("drvfs", "C:", "/mnt/c"));
        assert!(!is_drvfs("ext4", "/dev/sdc", "/"));
        assert!(!is_drvfs("9p", "wslg", "/mnt/wslg"));
    }

    #[test]
    fn pi_throttled_and_sd() {
        assert_eq!(parse_throttled("throttled=0x50005\n"), Some(0x50005));
        assert_eq!(parse_throttled("50000"), Some(0x50000));
        assert_eq!(parse_throttled("garbage"), None);
        assert_eq!(decode_throttled(0x50005), vec!["under-voltage now", "throttled now", "under-voltage has occurred since boot", "throttling has occurred since boot"]);
        assert!(decode_throttled(0).is_empty());
        let dm = "[    2.1] mmc0: new ultra high speed DDR50 SDHC card at address aaaa\n\
                  [ 9123.4] mmc0: timeout waiting for hardware interrupt.\n\
                  [ 9123.5] blk_update_request: I/O error, dev mmcblk0, sector 123 op 0x1:(WRITE)\n\
                  [ 9200.0] eth0: link up\n";
        let e = mmc_errors(dm);
        assert_eq!(e.len(), 2, "{e:?}");
        let ms = vec![
            storage::Mount { point: "/".into(), fstype: "ext4".into(), source: "/dev/mmcblk0p2".into(), opts: String::new() },
            storage::Mount { point: "/mnt/usb".into(), fstype: "ext4".into(), source: "/dev/sda1".into(), opts: String::new() },
        ];
        let sw = "Filename Type Size Used Priority\n/var/swap file 102396 0 -2\n/mnt/usb/swapfile file 1 0 -3\n/dev/zram0 partition 1 0 100\n";
        assert_eq!(swap_on_sd(sw, &ms), vec!["/var/swap"]);
    }

    #[test]
    fn docker_desktop_detection() {
        assert!(is_docker_desktop("6.10.14-linuxkit", ""));
        assert!(is_docker_desktop("", "Operating System: Docker Desktop\n"));
        assert!(!is_docker_desktop("6.8.0-49-generic", "Operating System: Ubuntu 24.04.1 LTS\n"));
    }

    #[test]
    fn tcc_areas() {
        let h = Path::new("/Users/alice");
        assert_eq!(tcc_area(Path::new("/Users/alice/Documents/divi"), h), Some("Documents"));
        assert_eq!(tcc_area(Path::new("/Users/alice/Desktop"), h), Some("Desktop"));
        assert_eq!(tcc_area(Path::new("/Volumes/Ext/irondivi"), h), Some("removable or network volume"));
        assert_eq!(tcc_area(Path::new("/Users/alice/Library/Application Support/IronDivi"), h), None);
        assert_eq!(tcc_area(Path::new("/Users/alice/Library/Mobile Documents/x"), h), Some("~/Library (protected subtree)"));
        assert_eq!(tcc_area(Path::new("/Users/alice/.irondivi"), h), None);
        let l = "2026-10-31T10:00:00Z ERROR opening /Users/alice/Documents/chain/LOCK: Operation not permitted (os error 1)";
        assert_eq!(tcc_log_line(l, h), Some("Documents"));
        assert_eq!(tcc_log_line("/Users/alice/.irondivi/LOCK: Operation not permitted", h), None);
        assert_eq!(tcc_log_line("opened /Users/alice/Documents/x fine", h), None);
    }
}
