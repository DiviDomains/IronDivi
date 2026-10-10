// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Runtime secret resolution (plan §3.3, `secret-management.md` §2).
//!
//! Keys are resolved into memory at startup and never written to disk, logged, or put on
//! argv. Two sources, no silent fallback between them:
//! - `op://vault/item/field` — `secret get --name <item> --op-ref <ref>` (the secret proxy:
//!   cache → `secret-broker` → 1Password CLI). Agent shells may not call the 1Password CLI
//!   directly: each raw call is a new 1Password session and a new Touch ID dialog
//!   (`secret-management.md` §2 rule 10). Resolve once per process;
//! - `credential:<name>` — a systemd `LoadCredential=` file under `$CREDENTIALS_DIRECTORY`
//!   (ramfs, readable only by the service), used on dnsdivi.

use std::process::Command;
use zeroize::Zeroizing;

use crate::error::{Result, SwapError};

/// Where a secret comes from. The reference itself is not secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// `op://vault/item/field`
    OnePassword(String),
    /// `credential:<name>` — systemd credential.
    SystemdCredential(String),
}

impl SecretRef {
    /// Parse `op://…` or `credential:<name>`.
    pub fn parse(s: &str) -> Result<Self> {
        if s.starts_with("op://") {
            Ok(SecretRef::OnePassword(s.to_string()))
        } else if let Some(name) = s.strip_prefix("credential:") {
            if name.is_empty() || name.contains('/') || name.contains("..") {
                return Err(SwapError::Secret(format!("bad credential name {name:?}")));
            }
            Ok(SecretRef::SystemdCredential(name.to_string()))
        } else {
            Err(SwapError::Secret(
                "secret reference must be op://… or credential:<name>".into(),
            ))
        }
    }

    /// Resolve into memory. The returned value is wiped on drop. Errors never contain it.
    pub fn resolve(&self) -> Result<Zeroizing<String>> {
        let value = match self {
            SecretRef::OnePassword(r) => {
                let out = Command::new("secret")
                    .args(["get", "--name", &cache_name(r), "--op-ref", r])
                    .stdin(std::process::Stdio::null())
                    .output()
                    .map_err(|e| SwapError::Secret(format!("cannot run secret: {e}")))?;
                let stdout = Zeroizing::new(out.stdout);
                if !out.status.success() {
                    // Exit 2: 1Password unavailable (nobody approved, or the broker is down): a pause.
                    return Err(SwapError::Secret(format!(
                        "secret get {r} failed (exit {:?}): {}",
                        out.status.code(),
                        String::from_utf8_lossy(&out.stderr).trim()
                    )));
                }
                Zeroizing::new(
                    String::from_utf8(stdout.to_vec())
                        .map_err(|_| SwapError::Secret(format!("{r} is not UTF-8")))?
                        .trim_end_matches(['\r', '\n'])
                        .to_string(),
                )
            }
            SecretRef::SystemdCredential(name) => {
                let dir = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
                    SwapError::Secret("CREDENTIALS_DIRECTORY not set (not under systemd?)".into())
                })?;
                let bytes = Zeroizing::new(
                    std::fs::read(std::path::Path::new(&dir).join(name))
                        .map_err(|e| SwapError::Secret(format!("credential {name}: {e}")))?,
                );
                Zeroizing::new(
                    String::from_utf8(bytes.to_vec())
                        .map_err(|_| SwapError::Secret(format!("credential {name} not UTF-8")))?
                        .trim_end()
                        .to_string(),
                )
            }
        };
        if value.is_empty() {
            return Err(SwapError::Secret("resolved secret is empty".into()));
        }
        Ok(value)
    }
}

/// Proxy cache key for an `op://vault/item/field` reference: item and field, slugged.
fn cache_name(r: &str) -> String {
    let path = r.trim_start_matches("op://");
    let tail = path.split_once('/').map_or(path, |(_, rest)| rest);
    let slug: String = tail
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    slug.split('-')
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_names() {
        assert_eq!(
            cache_name("op://global_secret_store/IronDivi Swap POC - taker-btc/password"),
            "irondivi-swap-poc-taker-btc-password"
        );
    }

    #[test]
    fn parse_refs() {
        assert!(matches!(
            SecretRef::parse("op://v/i/f").unwrap(),
            SecretRef::OnePassword(_)
        ));
        assert!(matches!(
            SecretRef::parse("credential:divi-wif").unwrap(),
            SecretRef::SystemdCredential(_)
        ));
        assert!(SecretRef::parse("env:FOO").is_err());
        assert!(SecretRef::parse("credential:../x").is_err());
    }
}
