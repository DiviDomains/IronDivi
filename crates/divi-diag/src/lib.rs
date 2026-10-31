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
//! `--send <folder>`; this build has no developer key, so nothing is sent.
//! Not in this crate yet: B3 observed start (`--run`) and the B6 recording
//! modes.

pub mod collectors;
pub mod consent;
pub mod ctx;
pub mod discovery;
pub mod frame;
pub mod import;
pub mod mem;
pub mod oldlog;
pub mod redact;
pub mod runner;
pub mod scanner;
pub mod tar;
pub mod util;

/// The node's own configuration parser (B1.3: "parsed with the node's
/// parser"). It lives in the irondivid binary crate and has no crate-local
/// dependencies, so it is compiled in here from the same file rather than
/// copied.
#[path = "../../../bin/irondivid/src/settings.rs"]
#[allow(dead_code, clippy::all)]
pub mod settings;

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
}

const USAGE: &str = "usage: irondivi-cli diag [--datadir DIR] [--conf FILE] [--run|--no-run] \
[--submit|--no-submit] [--out DIR] [--offline] [--no-fsync-test] [--report-file FILE]\n       \
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
    Ok(o)
}

/// Entry point for `irondivi-cli diag <args>`; returns the process exit code
pub fn run(args: &[String]) -> i32 {
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
