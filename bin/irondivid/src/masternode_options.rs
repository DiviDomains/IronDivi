// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The masternode start options as divid reads them: `-mnconf` (which file
//! is masternode.conf), the file itself and `-mnconflock`
//! (MasternodeModule.cpp:210-219, :454-466; masternodeconfig.cpp:33-90).

use crate::settings::Settings;
use std::path::{Path, PathBuf};

/// Divi Core's masternode.conf header, written when there is no file
/// (masternodeconfig.cpp:53-64)
pub const MASTERNODE_CONF_HEADER: &str = "# Masternode config file\n\
# Format: alias IP:port masternodeprivkey collateral_output_txid collateral_output_index\n\
# Example: mn1 127.0.0.2:51472 93HaYBVUCYjEMeeH1Y4sBGLALQZE1Yc1K64xiqgX37tGBDQL8Xg 2bcd3c84c84f87eaa86e4e56834c92927a07f9e18718810b92e0d0324456a67c 0\n";

/// One masternode.conf entry
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfLine {
    pub alias: String,
    pub ip: String,
    pub priv_key: String,
    pub tx_hash: String,
    pub out_idx: String,
}

#[derive(Debug, Clone)]
pub struct MasternodeOptions {
    /// masternode.conf: `-mnconf`, relative to the data directory
    pub conf_path: PathBuf,
    /// `-mnconflock`, default on: the entries' collateral is locked
    pub lock: bool,
}

impl MasternodeOptions {
    pub fn from_settings(settings: &Settings, data_dir: &Path) -> Self {
        let conf = PathBuf::from(settings.get("mnconf").unwrap_or("masternode.conf"));
        MasternodeOptions {
            // GetMasternodeConfigFile: a relative path is in the data directory
            // (masternodeconfig.cpp:33-38)
            conf_path: if conf.is_absolute() {
                conf
            } else {
                data_dir.join(conf)
            },
            lock: settings.get_bool("mnconflock", true),
        }
    }

    /// Read masternode.conf as CMasternodeConfig::read does: a missing file is
    /// made with divid's header and has no entry; a line that is not empty
    /// and does not start with `#` needs five words, else the start stops with
    /// divid's text (masternodeconfig.cpp:49-93, MasternodeModule.cpp:210-219)
    pub fn read_conf(&self) -> Result<Vec<ConfLine>, String> {
        let Ok(text) = std::fs::read(&self.conf_path) else {
            let _ = std::fs::write(&self.conf_path, MASTERNODE_CONF_HEADER);
            return Ok(Vec::new());
        };
        let text = String::from_utf8_lossy(&text);
        let mut entries = Vec::new();
        for (n, line) in text.split('\n').enumerate() {
            if line.is_empty() {
                continue;
            }
            let words: Vec<&str> = line.split_ascii_whitespace().collect();
            if words.first().is_some_and(|w| w.starts_with('#')) {
                continue;
            }
            if words.len() < 5 {
                return Err(format!(
                    "Error reading masternode configuration file: Could not parse masternode.conf\nLine: {}\n\"{}\"\n",
                    n + 1,
                    line
                ));
            }
            entries.push(ConfLine {
                alias: words[0].to_string(),
                ip: words[1].to_string(),
                priv_key: words[2].to_string(),
                tx_hash: words[3].to_string(),
                out_idx: words[4].to_string(),
            });
        }
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(lines: &[(&str, &str)], dir: &Path) -> MasternodeOptions {
        let mut s = Settings::default();
        for (k, v) in lines {
            s.set(k, v, false);
        }
        MasternodeOptions::from_settings(&s, dir)
    }

    /// -mnconf names masternode.conf, relative to the data directory; a missing
    /// one is made with divid's header; a line of fewer than five words stops
    /// the start with divid's text; -mnconflock defaults to on
    #[test]
    fn mnconf_and_masternode_conf_lines_as_divid() {
        let dir = tempfile::tempdir().unwrap();
        let o = opts(&[("mnconf", "sub.conf")], dir.path());
        assert_eq!(o.conf_path, dir.path().join("sub.conf"));
        assert!(o.lock);
        assert_eq!(o.read_conf(), Ok(vec![]));
        assert!(std::fs::read_to_string(dir.path().join("sub.conf"))
            .unwrap()
            .starts_with("# Masternode config file"));
        let abs = dir.path().join("abs.conf");
        let o = opts(
            &[("mnconf", abs.to_str().unwrap()), ("mnconflock", "0")],
            dir.path(),
        );
        assert_eq!(o.conf_path, abs);
        assert!(!o.lock);
        std::fs::write(
            &abs,
            "# c\n\nmn1 127.0.0.2:1 key tx 0\nmn2 127.0.0.2:2 tx\n",
        )
        .unwrap();
        assert_eq!(
            o.read_conf(),
            Err("Error reading masternode configuration file: Could not parse masternode.conf\nLine: 4\n\"mn2 127.0.0.2:2 tx\"\n".to_string())
        );
        std::fs::write(&abs, " \n").unwrap();
        assert!(o.read_conf().is_err(), "a line of spaces is no entry");
        std::fs::write(
            &abs,
            "  # indented comment\nmn1 127.0.0.2:1 key tx 0 extra\n",
        )
        .unwrap();
        assert_eq!(o.read_conf().unwrap().len(), 1);
    }
}
