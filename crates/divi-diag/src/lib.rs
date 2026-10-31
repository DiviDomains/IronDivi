// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! `irondivi-cli diag`: the collection half of IronDivi's diagnostics
//! (docs/plans/diag.md Part B: B1 discovery, B2 collectors, R1 output folder).
//!
//! The parent process discovers data dirs, nodes and binaries (B1.1), then
//! runs every collector as its own child process (`irondivi-cli diag
//! --collector <name>`, spawned from [`std::env::current_exe`]) with a time
//! budget and a memory cap. A collector writes framed output on its stdout
//! ([`frame`]); the parent scrubs every byte (§6.2 step 1, [`redact`])
//! before it reaches the package folder.
//!
//! `--import <folder|->` (B6.4, [`import`]) turns a contrib/diag.sh folder
//! into a package. §8 ([`consent`]): the user's report, the review, and
//! `--send <folder>`, which seals the package to the developer key (§8.4).
//! B3 ([`collectors::observed`]): with consent, irondivid is started once
//! and watched; `--exec-as` is its single-threaded id-switching helper.
//! `--attach <file>` (B6.6, [`attach`]): a file the user names, redacted,
//! JSON through the RPC answer layer ([`rpcjson`]). `--rpc <method>
//! [args…]` (B6.5, [`collectors::rpc`]): one allowlisted, clamped call to
//! the running node, its answer through the same layer. `--capture
//! <minutes> [--until <event>]` (B6.1, [`collectors::capture`]): a sample
//! every 10 s before the collection. Not in this crate yet: `--tx`,
//! `--rpc-clear` and the host package (B6.2).

pub mod attach;
pub mod collectors;
pub mod consent;
pub mod ctx;
pub mod discovery;
pub mod frame;
pub mod import;
pub mod mem;
pub mod oldlog;
pub mod redact;
pub mod rpcjson;
pub mod runner;
pub mod scanner;
pub mod tar;
pub mod upload;
pub mod util;

/// The node's own configuration parser (B1.3: "parsed with the node's
/// parser"), shared with irondivid through the `divi-settings` crate.
pub use divi_settings as settings;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Exit code for a usage error (BSD `EX_USAGE`)
pub const EX_USAGE: i32 = 64;

#[derive(Debug, Default, Clone)]
pub struct Options {
    pub datadir: Option<std::path::PathBuf>,
    pub conf: Option<std::path::PathBuf>,
    /// `--run` / `--no-run`; `None` = ask (B3)
    pub run: Option<bool>,
    /// `--submit` / `--no-submit`; `None` = ask (§8)
    pub submit: Option<bool>,
    pub out: Option<std::path::PathBuf>,
    pub offline: bool,
    pub fsync_test: Option<bool>,
    /// `--import <folder|->` (B6.4)
    pub import: Option<String>,
    /// `--keep-raw`: an imported diag.sh folder is not deleted afterwards
    pub keep_raw: bool,
    /// `--send <folder>`: review a kept folder again (§8.3, R2)
    pub send: Option<std::path::PathBuf>,
    /// `--report-file <path>`: the §8.1 answers, `## N` starts answer N
    pub report_file: Option<std::path::PathBuf>,
    /// `--attach <file>` with its `--attach-method <method>`, if any (B6.6)
    pub attach: Vec<(std::path::PathBuf, Option<String>)>,
    /// `--rpc <method> [args…]`: the method, then every word up to the
    /// next `--` option (B6.5)
    pub rpc: Vec<(String, Vec<String>)>,
    /// `--capture <minutes>` (B6.1)
    pub capture: Option<u64>,
    /// `--until <event>[,<event>]`, repeatable (B6.1)
    pub until: Vec<collectors::capture::Until>,
}

const USAGE: &str = "usage: irondivi-cli diag [--datadir DIR] [--conf FILE] [--run|--no-run] \
[--submit|--no-submit] [--out DIR] [--offline] [--no-fsync-test] [--report-file FILE] \
[--attach FILE [--attach-method METHOD]]... [--rpc METHOD [ARG...]]... \
[--capture MINUTES [--until exit|stall|'rss>MB'|'peers<N']...]\n       \
irondivi-cli diag --import <folder|-> [--keep-raw] [--out DIR] [--no-submit]\n       \
irondivi-cli diag --send <folder>";

pub fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options::default();
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        let (key, inline) = match a.split_once('=') {
            Some((k, v)) if k.starts_with("--") => (k, Some(v.to_string())),
            _ => (a, None),
        };
        let value = |i: &mut usize| -> Result<String, String> {
            if let Some(v) = inline.clone() {
                return Ok(v);
            }
            *i += 1;
            args.get(*i).cloned().ok_or_else(|| format!("{key} needs a value"))
        };
        match key {
            "--datadir" | "-datadir" => o.datadir = Some(value(&mut i)?.into()),
            "--conf" | "-conf" => o.conf = Some(value(&mut i)?.into()),
            "--out" => o.out = Some(value(&mut i)?.into()),
            "--run" => o.run = Some(true),
            "--no-run" => o.run = Some(false),
            "--submit" => o.submit = Some(true),
            "--no-submit" => o.submit = Some(false),
            "--offline" => o.offline = true,
            "--fsync-test" => o.fsync_test = Some(true),
            "--no-fsync-test" => o.fsync_test = Some(false),
            "--import" => o.import = Some(value(&mut i)?),
            "--keep-raw" => o.keep_raw = true,
            "--send" => o.send = Some(value(&mut i)?.into()),
            "--report-file" => o.report_file = Some(value(&mut i)?.into()),
            "--attach" => o.attach.push((value(&mut i)?.into(), None)),
            "--rpc" => {
                let m = value(&mut i)?;
                let mut words = Vec::new();
                while i + 1 < args.len() && !args[i + 1].starts_with("--") {
                    i += 1;
                    words.push(args[i].clone());
                }
                o.rpc.push((m, words));
            }
            "--capture" => {
                let v = value(&mut i)?;
                let m: u64 = v.parse().map_err(|_| format!("--capture {v}: minutes, a whole number"))?;
                if m == 0 || m > collectors::capture::MAX_MINUTES {
                    return Err(format!(
                        "--capture {m}: from 1 to {} minutes (7 days)",
                        collectors::capture::MAX_MINUTES
                    ));
                }
                o.capture = Some(m);
            }
            "--until" => {
                for w in value(&mut i)?.split(',').filter(|w| !w.trim().is_empty()) {
                    let u = collectors::capture::parse_until(w)?;
                    if !o.until.contains(&u) {
                        o.until.push(u);
                    }
                }
            }
            "--attach-method" => {
                let m = value(&mut i)?;
                match o.attach.last_mut() {
                    Some((_, l @ None)) => *l = Some(m),
                    _ => return Err("--attach-method names the method of the --attach just before it".into()),
                }
            }
            // R2: `--yes` is gone; it said yes to everything at once
            "--yes" | "-y" => {
                return Err("--yes was removed: consent is given per step. Use --run or \
                            --no-run for the observed start and --submit or --no-submit for \
                            sending; without a terminal nothing is ever sent."
                    .into())
            }
            "-h" | "--help" => return Err(String::new()),
            _ => return Err(format!("unknown option {a}")),
        }
        i += 1;
    }
    if !o.until.is_empty() && o.capture.is_none() {
        return Err("--until belongs to --capture".into());
    }
    Ok(o)
}

/// Entry point for `irondivi-cli diag <args>`; returns the process exit code
pub fn run(args: &[String]) -> i32 {
    if args.first().map(String::as_str) == Some("--exec-as") {
        return collectors::observed::exec_as(&args[1..]);
    }
    if args.first().map(String::as_str) == Some("--collector") {
        return match args.get(1) {
            Some(name) => runner::child_main(name),
            None => EX_USAGE,
        };
    }
    match parse_options(args) {
        Ok(o) => match (o.import.clone(), o.send.clone()) {
            (Some(_), Some(_)) => {
                eprintln!("irondivi-cli diag: --import and --send cannot be used together\n{USAGE}");
                EX_USAGE
            }
            (i, s) if !o.rpc.is_empty() && (i.is_some() || s.is_some()) => {
                eprintln!("irondivi-cli diag: --rpc is part of a collection run, not of --import or --send\n{USAGE}");
                EX_USAGE
            }
            (i, s) if o.capture.is_some() && (i.is_some() || s.is_some()) => {
                eprintln!("irondivi-cli diag: --capture is part of a collection run, not of --import or --send\n{USAGE}");
                EX_USAGE
            }
            (i, s) if !o.attach.is_empty() && (i.is_some() || s.is_some()) => {
                eprintln!("irondivi-cli diag: --attach is part of a collection run, not of --import or --send\n{USAGE}");
                EX_USAGE
            }
            (Some(src), None) => import::import_main(&src, &o),
            (None, Some(folder)) => consent::send_main(&folder, &o),
            (None, None) => runner::parent_main(o),
        },
        Err(e) => {
            if !e.is_empty() {
                eprintln!("irondivi-cli diag: {e}");
            }
            eprintln!("{USAGE}");
            if e.is_empty() {
                0
            } else {
                EX_USAGE
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn yes_is_refused_with_exit_64() {
        assert!(parse_options(&s(&["--yes"])).unwrap_err().contains("--submit"));
        assert_eq!(run(&s(&["--yes"])), EX_USAGE);
    }

    #[test]
    fn rpc_options() {
        let o = parse_options(&s(&["--rpc", "listtransactions", "*", "5000", "--rpc", "getblockcount", "--offline"])).unwrap();
        assert_eq!(o.rpc, vec![("listtransactions".to_string(), s(&["*", "5000"])), ("getblockcount".to_string(), vec![])]);
        assert!(o.offline);
        assert!(parse_options(&s(&["--rpc"])).is_err());
    }

    #[test]
    fn capture_options() {
        use collectors::capture::Until;
        let o = parse_options(&s(&["--capture", "90", "--until", "exit,rss>4000", "--until=peers<3"])).unwrap();
        assert_eq!(o.capture, Some(90));
        assert_eq!(o.until, vec![Until::Exit, Until::RssOver(4000), Until::PeersUnder(3)]);
        assert!(parse_options(&s(&["--capture", "0"])).is_err());
        assert!(parse_options(&s(&["--capture", "10081"])).is_err());
        assert!(parse_options(&s(&["--capture", "10080"])).is_ok());
        assert!(parse_options(&s(&["--until", "exit"])).unwrap_err().contains("--capture"));
        assert!(parse_options(&s(&["--capture", "5", "--until", "fork"])).is_err());
        assert_eq!(run(&s(&["--capture", "5", "--send", "x"])), EX_USAGE);
    }

    #[test]
    fn attach_options() {
        let o = parse_options(&s(&["--attach", "a.json", "--attach-method=listunspent", "--attach", "b.log"])).unwrap();
        assert_eq!(o.attach.len(), 2);
        assert_eq!(o.attach[0].1.as_deref(), Some("listunspent"));
        assert_eq!(o.attach[1].1, None);
        assert!(parse_options(&s(&["--attach-method", "getbalance"])).is_err());
        assert!(parse_options(&s(&["--attach", "a", "--attach-method", "x", "--attach-method", "y"])).is_err());
    }

    #[test]
    fn options_parse() {
        let o = parse_options(&s(&["--datadir", "/d", "--conf=/c", "--no-run", "--submit", "--out", "o"]))
            .unwrap();
        assert_eq!(o.datadir.unwrap().to_str(), Some("/d"));
        assert_eq!(o.conf.unwrap().to_str(), Some("/c"));
        assert_eq!(o.run, Some(false));
        assert_eq!(o.submit, Some(true));
        assert!(parse_options(&s(&["--bogus"])).is_err());
    }
}
