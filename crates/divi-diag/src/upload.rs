// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! §8.4 upload: after `yes` and sealing, one HTTPS `PUT` of the sealed
//! package to the §9 receiver ([`RECEIVER`]).
//!
//! - Contacted only here, after consent; nothing earlier probes it.
//! - TLS: the Mozilla roots compiled in (`webpki-roots`), plus the system
//!   store where one exists. `HTTPS_PROXY` / `NO_PROXY` are honoured.
//!   Not done (§9): no public-key pin and no second receiver host.
//! - On success the ticket and the ciphertext's SHA-256 are printed and
//!   appended to the folder's `diag.log`; on failure the cause is named,
//!   written to `diag.log` too, and the sealed file stays where it is with
//!   instructions for sending it by hand (§8.4's fallback).
//! - `--offline` skips the upload; the sealed file is the result.
//!
//! The receiver address can be overridden with `IRONDIVI_DIAG_RECEIVER`
//! (a full `…/v1/upload` URL; `http://` only for a loopback address), for
//! tests.

use std::io::Write;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

/// The §9 receiver
pub const RECEIVER: &str = "https://diag.irondivi.com/v1/upload";
pub const RETENTION_DAYS: u64 = 90;

/// Said with the send question (§9: hosting and retention are stated in
/// the send prompt)
pub fn prompt_note(offline: bool) -> String {
    if offline {
        "--offline: after yes the encrypted package is only written beside the folder; nothing is uploaded.\n".into()
    } else {
        format!(
            "After yes the package is encrypted to the developer's key, then uploaded to {host} \
             (a server the developer runs; it keeps no record of your address, and deletes the \
             package {RETENTION_DAYS} days after it arrives or when your ticket is closed).\n",
            host = host_of(&receiver())
        )
    }
}

pub fn receiver() -> String {
    match std::env::var("IRONDIVI_DIAG_RECEIVER") {
        Ok(u) if u.starts_with("https://") || is_loopback_http(&u) => u,
        _ => RECEIVER.into(),
    }
}

fn is_loopback_http(u: &str) -> bool {
    ["http://127.0.0.1:", "http://[::1]:", "http://localhost:"].iter().any(|p| u.starts_with(p))
}

fn host_of(u: &str) -> &str {
    let s = u.split_once("://").map(|x| x.1).unwrap_or(u);
    s.split('/').next().unwrap_or(s)
}

#[derive(Debug, PartialEq)]
pub struct Receipt {
    pub ticket: String,
    pub sha256: String,
}

/// Why an upload failed, named (§8.4)
pub fn upload(url: &str, ct: &[u8]) -> Result<Receipt, String> {
    let c = reqwest::blocking::Client::builder()
        .connect_timeout(Duration::from_secs(20))
        // 100 MiB at a slow 200 kB/s, with room
        .timeout(Duration::from_secs(15 * 60))
        .build()
        .map_err(|e| format!("cannot start HTTPS: {e}"))?;
    let want = hex::encode(Sha256::digest(ct));
    let r = c
        .put(url)
        .header("content-type", "application/octet-stream")
        .body(ct.to_vec())
        .send()
        .map_err(|e| cause(&e, url, ct.len()))?;
    let code = r.status();
    let server_date = r.headers().get("date").and_then(|v| v.to_str().ok()).map(str::to_string);
    let body = r.text().unwrap_or_default();
    if !code.is_success() {
        // a proxy answers CONNECT itself; the receiver's refusals are plain text
        let who = if code.as_u16() == 407 || code.as_u16() == 502 && body.to_ascii_lowercase().contains("proxy") {
            "proxy refused"
        } else {
            "refused by receiver"
        };
        let _ = server_date;
        return Err(format!("{who}: {code}: {}", one_line(&body)));
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| format!("refused by receiver: unreadable answer: {}", one_line(&body)))?;
    let ticket = v["ticket"].as_str().unwrap_or_default().to_string();
    let sha256 = v["sha256"].as_str().unwrap_or_default().to_string();
    if ticket.len() != 8 || !ticket.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(format!("refused by receiver: no ticket in the answer: {}", one_line(&body)));
    }
    if sha256 != want {
        return Err(format!("damaged in transit: the receiver got SHA-256 {sha256}, this machine sent {want} (ticket {ticket})"));
    }
    Ok(Receipt { ticket, sha256 })
}

fn one_line(s: &str) -> String {
    let t: String = s.trim().chars().take(200).collect();
    t.replace('\n', " ")
}

/// The named cause of a transport error
fn cause(e: &reqwest::Error, url: &str, len: usize) -> String {
    let mut chain = format!("{e}");
    let mut src: Option<&dyn std::error::Error> = std::error::Error::source(e);
    while let Some(s) = src {
        chain.push_str(": ");
        chain.push_str(&s.to_string());
        src = s.source();
    }
    let l = chain.to_ascii_lowercase();
    let host = host_of(url);
    if e.is_timeout() {
        return format!("timed out talking to {host} (sending {len} bytes): {chain}");
    }
    if l.contains("expired") || l.contains("notvalidyet") || l.contains("not valid yet") {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        return format!(
            "clock wrong: the receiver's certificate is not valid at this machine's time (unix {now}); check the date: {chain}"
        );
    }
    if l.contains("certificate") || l.contains("unknownissuer") || l.contains("tls") || l.contains("handshake") {
        return format!(
            "TLS failed: the connection to {host} did not verify (a company proxy or antivirus that inspects HTTPS \
             can cause this; the encrypted file is still safe to send another way): {chain}"
        );
    }
    if l.contains("proxy") {
        return format!("proxy refused: {chain}");
    }
    if l.contains("dns") || l.contains("resolve") || l.contains("lookup") || l.contains("name or service") {
        return format!("no route / DNS failed: {host} did not resolve: {chain}");
    }
    if e.is_connect() {
        return format!("no route: cannot connect to {host}: {chain}");
    }
    format!("upload failed: {chain}")
}

fn log(root: &Path, line: &str) {
    // only an existing diag.log: a new file would be refused at a later --send
    let p = root.join("diag.log");
    if !p.is_file() {
        return;
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(p) {
        let _ = writeln!(f, "{line}");
    }
}

/// After [`crate::consent::Outcome::Sealed`]: upload `sealed` unless
/// `offline`. `true` when the developer has it (uploaded), `false` when
/// the file must be sent by hand.
pub fn after_seal(root: &Path, sealed: &Path, offline: bool) -> bool {
    let by_hand = format!(
        "The encrypted file stays at {}\nSend it to the developer any other way (e-mail or chat attachment, or \
         https://github.com/DiviDomains/IronDivi/issues). It is safe to send through any channel: only the \
         developer's private key can open it.",
        sealed.display()
    );
    if offline {
        println!("--offline: nothing was uploaded. {by_hand}");
        log(root, "upload: skipped (--offline)");
        return false;
    }
    let ct = match std::fs::read(sealed) {
        Ok(c) => c,
        Err(e) => {
            println!("Upload not attempted: {}: {}. {by_hand}", sealed.display(), e.kind());
            return false;
        }
    };
    let url = receiver();
    println!("Uploading {} bytes to {} ...", ct.len(), host_of(&url));
    match upload(&url, &ct) {
        Ok(r) => {
            println!(
                "Uploaded. Your ticket is {t}\nQuote {t} in your report to the developer. The receiver deletes the \
                 package {RETENTION_DAYS} days after today, or when the ticket is closed.\n(SHA-256 {s}; the local \
                 copy {p} can be deleted.)",
                t = r.ticket,
                s = r.sha256,
                p = sealed.display()
            );
            log(root, &format!("upload: ticket {} sha256 {} to {}", r.ticket, r.sha256, host_of(&url)));
            true
        }
        Err(why) => {
            println!("Upload failed: {why}\n{by_hand}");
            log(root, &format!("upload: failed: {why}"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read};
    use std::net::TcpListener;

    /// One HTTP exchange on loopback: returns the URL; the server answers
    /// `status` and `body`, and sends what it received down the channel
    fn serve_once(status: &'static str, body: impl Fn(&[u8]) -> String + Send + 'static) -> (String, std::sync::mpsc::Receiver<Vec<u8>>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/upload", l.local_addr().unwrap());
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut len = 0usize;
            loop {
                let mut h = String::new();
                r.read_line(&mut h).unwrap();
                if h == "\r\n" || h.is_empty() {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).unwrap();
            let out = body(&b);
            let mut s = s;
            write!(s, "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}", out.len()).unwrap();
            tx.send(b).unwrap();
        });
        (url, rx)
    }

    #[test]
    fn success_gives_the_ticket_and_checks_the_hash() {
        let (url, rx) = serve_once("201 Created", |b| {
            format!(r#"{{"ticket":"ABCD2345","sha256":"{}","size":{}}}"#, hex::encode(Sha256::digest(b)), b.len())
        });
        let ct = b"age-encryption.org/v1\nrest".to_vec();
        let r = upload(&url, &ct).unwrap();
        assert_eq!(r.ticket, "ABCD2345");
        assert_eq!(rx.recv().unwrap(), ct);
    }

    #[test]
    fn a_wrong_hash_is_named() {
        let (url, _rx) = serve_once("201 Created", |_| r#"{"ticket":"ABCD2345","sha256":"00","size":1}"#.into());
        assert!(upload(&url, b"x").unwrap_err().starts_with("damaged in transit"));
    }

    #[test]
    fn refusals_carry_status_and_message() {
        let (url, _rx) = serve_once("429 Too Many Requests", |_| "rate limited: 10 uploads an hour\n".into());
        let e = upload(&url, b"x").unwrap_err();
        assert!(e.starts_with("refused by receiver: 429"), "{e}");
        assert!(e.contains("10 uploads an hour"), "{e}");
    }

    #[test]
    fn nothing_listening_is_no_route() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/upload", l.local_addr().unwrap());
        drop(l);
        let e = upload(&url, b"x").unwrap_err();
        assert!(e.starts_with("no route"), "{e}");
    }

    #[test]
    fn failure_keeps_the_file_and_logs_the_cause() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().join("f");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(root.join("diag.log"), "start\n").unwrap();
        let sealed = d.path().join("f.age");
        std::fs::write(&sealed, b"age-encryption.org/v1\n").unwrap();
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/v1/upload", l.local_addr().unwrap());
        drop(l);
        std::env::set_var("IRONDIVI_DIAG_RECEIVER", &url);
        assert!(!after_seal(&root, &sealed, false));
        std::env::remove_var("IRONDIVI_DIAG_RECEIVER");
        assert!(sealed.exists());
        let log = std::fs::read_to_string(root.join("diag.log")).unwrap();
        assert!(log.contains("upload: failed: no route"), "{log}");
        assert!(!after_seal(&root, &sealed, true));
        assert!(std::fs::read_to_string(root.join("diag.log")).unwrap().contains("skipped (--offline)"));
    }

    #[test]
    fn receiver_override_is_https_or_loopback_only() {
        assert!(is_loopback_http("http://127.0.0.1:9/v1/upload"));
        assert!(!is_loopback_http("http://example.com/v1/upload"));
        assert_eq!(host_of(RECEIVER), "diag.irondivi.com");
    }
}
