// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Who may use the web interface: one admin password, its Argon2id hash kept
//! in `<datadir>/webui-auth.json` (never in the config file); a one-time setup
//! token in `<datadir>/webui-setup-token` until that password is chosen;
//! sessions held in memory, each with its own CSRF token; and a back-off on
//! failed logins.

use argon2::{Algorithm, Argon2, Params, Version};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

/// The password file in the data directory
pub const AUTH_FILE: &str = "webui-auth.json";
/// The setup token file, there until the admin password is chosen
pub const SETUP_TOKEN_FILE: &str = "webui-setup-token";
/// The session cookie's name
pub const COOKIE_NAME: &str = "irondivi_webui";
/// Shortest admin password accepted
pub const MIN_PASSWORD_LEN: usize = 12;

/// A session ends after this long without a request
const SESSION_IDLE: Duration = Duration::from_secs(30 * 60);
/// and after this long in any case
const SESSION_MAX: Duration = Duration::from_secs(12 * 60 * 60);
/// Sessions kept at once; the oldest goes first
const MAX_SESSIONS: usize = 32;
/// Failed logins from one address before each further one waits
const FREE_FAILURES: u32 = 5;
/// The longest a failed login makes the next one wait
const MAX_BACKOFF: Duration = Duration::from_secs(300);

/// OWASP's Argon2id minimum (19 MiB, 2 passes): a login costs tens of
/// milliseconds, a guess as much
const ARGON2_M_KIB: u32 = 19 * 1024;
const ARGON2_T: u32 = 2;
const ARGON2_P: u32 = 1;

/// The stored password: its Argon2id hash with the salt and costs used
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PasswordRecord {
    version: u32,
    salt: String,
    hash: String,
    m_kib: u32,
    t: u32,
    p: u32,
}

fn argon2_hash(password: &str, salt: &[u8], m_kib: u32, t: u32, p: u32) -> Option<[u8; 32]> {
    let params = Params::new(m_kib, t, p, Some(32)).ok()?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .ok()?;
    Some(out)
}

/// Equal without returning early on the first differing byte
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Write `content` to `path` readable by the owner alone, replacing it whole
pub fn write_private(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("webui")
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    file.write_all(content)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)
}

/// The admin password and the setup token
pub struct AuthStore {
    path: PathBuf,
    token_path: PathBuf,
    record: Mutex<Option<PasswordRecord>>,
    /// SHA-256 of the setup token while no password is set
    setup_token: Mutex<Option<[u8; 32]>>,
}

impl AuthStore {
    /// Read the password file in `data_dir`. Without one, a new setup token is
    /// written for the first visitor to prove they can read the data directory.
    pub fn open(data_dir: &Path) -> anyhow::Result<AuthStore> {
        let path = data_dir.join(AUTH_FILE);
        let token_path = data_dir.join(SETUP_TOKEN_FILE);
        let record = match std::fs::read_to_string(&path) {
            Ok(text) => Some(
                serde_json::from_str::<PasswordRecord>(&text)
                    .map_err(|e| anyhow::anyhow!("{} is not readable: {}", path.display(), e))?,
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(anyhow::anyhow!("cannot read {}: {}", path.display(), e)),
        };
        let store = AuthStore {
            path,
            token_path,
            record: Mutex::new(record),
            setup_token: Mutex::new(None),
        };
        if store.record.lock().is_none() {
            store.new_setup_token()?;
        } else {
            // A token left from an earlier setup is no use any more
            let _ = std::fs::remove_file(&store.token_path);
        }
        Ok(store)
    }

    fn new_setup_token(&self) -> anyhow::Result<()> {
        let token = Zeroizing::new(random_hex(24));
        write_private(&self.token_path, token.as_bytes())
            .map_err(|e| anyhow::anyhow!("cannot write {}: {}", self.token_path.display(), e))?;
        *self.setup_token.lock() = Some(Sha256::digest(token.as_bytes()).into());
        Ok(())
    }

    /// The file a first visitor reads the setup token from
    pub fn setup_token_path(&self) -> &Path {
        &self.token_path
    }

    pub fn setup_required(&self) -> bool {
        self.record.lock().is_none()
    }

    /// Whether `token` is the setup token (while one is outstanding)
    pub fn check_setup_token(&self, token: &str) -> bool {
        let digest: [u8; 32] = Sha256::digest(token.trim().as_bytes()).into();
        self.setup_token
            .lock()
            .as_ref()
            .is_some_and(|t| constant_time_eq(t, &digest))
    }

    /// Hash and store a new admin password; ends the setup token
    pub fn set_password(&self, password: &str) -> anyhow::Result<()> {
        if password.chars().count() < MIN_PASSWORD_LEN {
            anyhow::bail!("The password must be at least {MIN_PASSWORD_LEN} characters");
        }
        let mut salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let hash = argon2_hash(password, &salt, ARGON2_M_KIB, ARGON2_T, ARGON2_P)
            .ok_or_else(|| anyhow::anyhow!("password hashing failed"))?;
        let record = PasswordRecord {
            version: 1,
            salt: hex::encode(salt),
            hash: hex::encode(hash),
            m_kib: ARGON2_M_KIB,
            t: ARGON2_T,
            p: ARGON2_P,
        };
        let text = serde_json::to_vec_pretty(&record)?;
        write_private(&self.path, &text)
            .map_err(|e| anyhow::anyhow!("cannot write {}: {}", self.path.display(), e))?;
        *self.record.lock() = Some(record);
        *self.setup_token.lock() = None;
        let _ = std::fs::remove_file(&self.token_path);
        Ok(())
    }

    /// Whether `password` is the admin password. Costs one Argon2id hash.
    pub fn verify(&self, password: &str) -> bool {
        let Some(record) = self.record.lock().clone() else {
            return false;
        };
        let (Ok(salt), Ok(expected)) = (hex::decode(&record.salt), hex::decode(&record.hash))
        else {
            return false;
        };
        argon2_hash(password, &salt, record.m_kib, record.t, record.p)
            .is_some_and(|h| constant_time_eq(&h, &expected))
    }
}

#[derive(Debug, Clone)]
struct Session {
    csrf: String,
    created: Instant,
    last_seen: Instant,
}

/// Signed-in browsers, by the SHA-256 of their cookie
#[derive(Default)]
pub struct Sessions {
    map: Mutex<HashMap<[u8; 32], Session>>,
}

/// A new session's cookie value and CSRF token
pub struct NewSession {
    pub cookie: String,
    pub csrf: String,
}

fn cookie_key(cookie: &str) -> [u8; 32] {
    Sha256::digest(cookie.as_bytes()).into()
}

impl Sessions {
    pub fn create(&self) -> NewSession {
        let cookie = random_hex(32);
        let csrf = random_hex(24);
        let now = Instant::now();
        let mut map = self.map.lock();
        map.retain(|_, s| live(s, now));
        while map.len() >= MAX_SESSIONS {
            let oldest = map.iter().min_by_key(|(_, s)| s.created).map(|(k, _)| *k);
            match oldest {
                Some(k) => map.remove(&k),
                None => break,
            };
        }
        map.insert(
            cookie_key(&cookie),
            Session {
                csrf: csrf.clone(),
                created: now,
                last_seen: now,
            },
        );
        NewSession { cookie, csrf }
    }

    /// The session's CSRF token if `cookie` is a live session; marks it seen
    pub fn touch(&self, cookie: &str) -> Option<String> {
        let now = Instant::now();
        let mut map = self.map.lock();
        let key = cookie_key(cookie);
        match map.get_mut(&key) {
            Some(s) if live(s, now) => {
                s.last_seen = now;
                Some(s.csrf.clone())
            }
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }

    pub fn remove(&self, cookie: &str) {
        self.map.lock().remove(&cookie_key(cookie));
    }

    /// End every session (after the password changes), keeping `keep`
    pub fn remove_all_but(&self, keep: Option<&str>) {
        let keep = keep.map(cookie_key);
        self.map.lock().retain(|k, _| Some(*k) == keep);
    }
}

fn live(s: &Session, now: Instant) -> bool {
    now.duration_since(s.last_seen) < SESSION_IDLE && now.duration_since(s.created) < SESSION_MAX
}

#[derive(Debug, Clone, Copy)]
struct Failures {
    count: u32,
    until: Instant,
}

/// Failed logins by address: after a few, each failure doubles the wait
#[derive(Default)]
pub struct LoginLimiter {
    map: Mutex<HashMap<IpAddr, Failures>>,
}

impl LoginLimiter {
    /// How long `ip` must still wait before trying again, if at all
    pub fn wait(&self, ip: IpAddr) -> Option<Duration> {
        let now = Instant::now();
        self.map
            .lock()
            .get(&ip)
            .and_then(|f| f.until.checked_duration_since(now))
            .filter(|d| !d.is_zero())
    }

    pub fn failed(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut map = self.map.lock();
        if map.len() > 10_000 {
            map.retain(|_, f| f.until > now);
        }
        let f = map.entry(ip).or_insert(Failures {
            count: 0,
            until: now,
        });
        f.count += 1;
        if f.count >= FREE_FAILURES {
            let secs = 1u64 << (f.count - FREE_FAILURES).min(16);
            f.until = now + Duration::from_secs(secs).min(MAX_BACKOFF);
        }
    }

    pub fn succeeded(&self, ip: IpAddr) {
        self.map.lock().remove(&ip);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_token_then_password() {
        let dir = tempfile::tempdir().unwrap();
        let store = AuthStore::open(dir.path()).unwrap();
        assert!(store.setup_required());
        let token = std::fs::read_to_string(dir.path().join(SETUP_TOKEN_FILE)).unwrap();
        assert!(store.check_setup_token(&token));
        assert!(!store.check_setup_token("wrong"));
        assert!(store.set_password("short").is_err());
        store.set_password("correct horse battery").unwrap();
        assert!(!store.setup_required());
        assert!(
            !dir.path().join(SETUP_TOKEN_FILE).exists(),
            "the token goes once used"
        );
        assert!(!store.check_setup_token(&token));
        assert!(store.verify("correct horse battery"));
        assert!(!store.verify("correct horse batterY"));

        // The hash survives a restart; no new token is written
        let again = AuthStore::open(dir.path()).unwrap();
        assert!(!again.setup_required());
        assert!(again.verify("correct horse battery"));
        assert!(!dir.path().join(SETUP_TOKEN_FILE).exists());
        let text = std::fs::read_to_string(dir.path().join(AUTH_FILE)).unwrap();
        assert!(!text.contains("correct horse"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(AUTH_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn sessions_live_and_end() {
        let sessions = Sessions::default();
        let a = sessions.create();
        let b = sessions.create();
        assert_eq!(sessions.touch(&a.cookie).as_deref(), Some(a.csrf.as_str()));
        assert!(sessions.touch("not-a-session").is_none());
        sessions.remove_all_but(Some(&b.cookie));
        assert!(sessions.touch(&a.cookie).is_none());
        assert!(sessions.touch(&b.cookie).is_some());
        sessions.remove(&b.cookie);
        assert!(sessions.touch(&b.cookie).is_none());
    }

    #[test]
    fn login_backoff_after_free_failures() {
        let limiter = LoginLimiter::default();
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..FREE_FAILURES - 1 {
            limiter.failed(ip);
            assert!(limiter.wait(ip).is_none());
        }
        limiter.failed(ip);
        assert!(limiter.wait(ip).is_some());
        limiter.succeeded(ip);
        assert!(limiter.wait(ip).is_none());
    }
}
