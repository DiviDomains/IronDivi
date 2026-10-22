// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! RPC cookie authentication
//!
//! When no `rpcuser`/`rpcpassword` pair is configured the server still
//! requires authentication: it writes a random secret to `<datadir>/.cookie`
//! (owner-only), and local clients such as `irondivi-cli` read it from there.
//! The file is removed when the server shuts down cleanly.

use rand::RngCore;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

/// User name written to the cookie file (as in Bitcoin Core).
pub const COOKIE_AUTH_USER: &str = "__cookie__";

/// Cookie file name inside the data directory.
pub const COOKIE_FILE_NAME: &str = ".cookie";

/// A cookie file on disk, removed again on drop.
pub struct AuthCookie {
    path: PathBuf,
    password: String,
}

impl AuthCookie {
    /// Write a fresh random cookie to `<dir>/.cookie` with mode 0600.
    pub fn generate(dir: &Path) -> io::Result<Self> {
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let password = hex::encode(secret);

        let path = dir.join(COOKIE_FILE_NAME);
        let tmp = dir.join(format!("{}.tmp", COOKIE_FILE_NAME));
        let _ = fs::remove_file(&tmp);

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(format!("{}:{}", COOKIE_AUTH_USER, password).as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, &path)?;

        Ok(AuthCookie { path, password })
    }

    /// Path of the cookie file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// User name to authenticate with.
    pub fn username(&self) -> &str {
        COOKIE_AUTH_USER
    }

    /// Secret to authenticate with.
    pub fn password(&self) -> &str {
        &self.password
    }
}

impl std::fmt::Debug for AuthCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCookie")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for AuthCookie {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Credentials the RPC server enforces, and the cookie that backs them when
/// no complete `rpcuser`/`rpcpassword` pair is configured.
pub fn resolve_rpc_auth(
    username: Option<&str>,
    password: Option<&str>,
    data_dir: &Path,
) -> io::Result<(String, String, Option<AuthCookie>)> {
    match (username, password) {
        (Some(u), Some(p)) if !u.is_empty() && !p.is_empty() => {
            Ok((u.to_string(), p.to_string(), None))
        }
        _ => {
            let cookie = AuthCookie::generate(data_dir)?;
            Ok((
                cookie.username().to_string(),
                cookie.password().to_string(),
                Some(cookie),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_is_owner_only_random_and_removed_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let cookie = AuthCookie::generate(dir.path()).unwrap();
        let path = dir.path().join(COOKIE_FILE_NAME);
        assert_eq!(cookie.path(), path);

        let contents = fs::read_to_string(&path).unwrap();
        let (user, secret) = contents.split_once(':').unwrap();
        assert_eq!(user, COOKIE_AUTH_USER);
        assert_eq!(secret, cookie.password());
        assert_eq!(secret.len(), 64);
        assert!(secret.bytes().all(|b| b.is_ascii_hexdigit()));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let second = AuthCookie::generate(tempfile::tempdir().unwrap().path()).unwrap();
        assert_ne!(second.password(), cookie.password());

        drop(cookie);
        assert!(!path.exists());
    }

    #[test]
    fn configured_credentials_win_otherwise_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let (u, p, cookie) = resolve_rpc_auth(Some("alice"), Some("s3cret"), dir.path()).unwrap();
        assert_eq!((u.as_str(), p.as_str()), ("alice", "s3cret"));
        assert!(cookie.is_none());
        assert!(!dir.path().join(COOKIE_FILE_NAME).exists());

        for (user, pass) in [(None, None), (Some("alice"), None), (None, Some("x"))] {
            let (u, p, cookie) = resolve_rpc_auth(user, pass, dir.path()).unwrap();
            assert_eq!(u, COOKIE_AUTH_USER);
            assert_eq!(p.len(), 64);
            assert!(cookie.is_some());
            assert!(dir.path().join(COOKIE_FILE_NAME).exists());
        }
    }
}
