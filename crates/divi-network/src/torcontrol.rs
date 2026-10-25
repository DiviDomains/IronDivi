//! The Tor controller (Divi Core torcontrol.cpp): with `-listenonion` it
//! connects to the Tor control port (`-torcontrol`), authenticates, and asks
//! Tor for a hidden service that forwards to the listen port. The service is
//! then one of the node's local addresses, and its key is kept in the data
//! directory's `onion_private_key` for the next start.

use crate::local::LOCAL_MANUAL;
use crate::peer_manager::PeerManager;
use crate::socks5::Proxy;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info};

/// The default control port (DEFAULT_TOR_CONTROL, defaultValues.h:23)
pub const DEFAULT_TOR_CONTROL: &str = "127.0.0.1:9051";

const TOR_COOKIE_SIZE: usize = 32;
const TOR_NONCE_SIZE: usize = 32;
const TOR_SAFE_SERVERKEY: &str = "Tor safe cookie authentication server-to-controller hash";
const TOR_SAFE_CLIENTKEY: &str = "Tor safe cookie authentication controller-to-server hash";
const RECONNECT_TIMEOUT_START: f64 = 1.0;
const RECONNECT_TIMEOUT_EXP: f64 = 1.5;
const MAX_LINE_LENGTH: usize = 100_000;

/// What the controller is started with
#[derive(Debug, Clone)]
pub struct TorControl {
    /// `-torcontrol`: a numeric `ip:port`
    pub target: String,
    /// `-torpassword`, empty for none
    pub password: String,
    /// Where the service key is kept (`<datadir>/onion_private_key`)
    pub private_key_file: PathBuf,
    /// Point onion peers at 127.0.0.1:9050 once Tor answers: only when
    /// `-onion` is not given (torcontrol.cpp:533-539)
    pub set_onion_proxy: bool,
}

/// A reply: its status code and the text of each line after the code
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Reply {
    code: u16,
    lines: Vec<String>,
}

/// Split a reply line as `AUTH METHODS=...` into its type and the rest
/// (SplitTorReplyLine, torcontrol.cpp:261-272)
fn split_reply_line(s: &str) -> (&str, &str) {
    match s.split_once(' ') {
        Some((t, rest)) => (t, rest),
        None => (s, ""),
    }
}

/// Parse `KEY=value KEY="quoted"` arguments; empty on a malformed line
/// (ParseTorReplyMapping, torcontrol.cpp:280-364)
fn parse_reply_mapping(s: &str) -> BTreeMap<String, String> {
    let s = s.as_bytes();
    let mut mapping = BTreeMap::new();
    let mut ptr = 0;
    while ptr < s.len() {
        let mut key = Vec::new();
        while ptr < s.len() && s[ptr] != b'=' && s[ptr] != b' ' {
            key.push(s[ptr]);
            ptr += 1;
        }
        if ptr == s.len() {
            return BTreeMap::new();
        }
        if s[ptr] == b' ' {
            break;
        }
        ptr += 1;
        let mut value = Vec::new();
        if ptr < s.len() && s[ptr] == b'"' {
            ptr += 1;
            let mut escape_next = false;
            while ptr < s.len() && (escape_next || s[ptr] != b'"') {
                escape_next = s[ptr] == b'\\' && !escape_next;
                value.push(s[ptr]);
                ptr += 1;
            }
            if ptr == s.len() {
                return BTreeMap::new();
            }
            ptr += 1;
            value = unescape(&value);
        } else {
            while ptr < s.len() && s[ptr] != b' ' {
                value.push(s[ptr]);
                ptr += 1;
            }
        }
        if ptr < s.len() && s[ptr] == b' ' {
            ptr += 1;
        }
        mapping.insert(
            String::from_utf8_lossy(&key).into_owned(),
            String::from_utf8_lossy(&value).into_owned(),
        );
    }
    mapping
}

/// The C escapes of a quoted value (control-spec 2.1.1, torcontrol.cpp:319-350)
fn unescape(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < value.len() {
        if value[i] == b'\\' && i + 1 < value.len() {
            i += 1;
            match value[i] {
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'r' => out.push(b'\r'),
                b'0'..=b'7' => {
                    let mut j = 1;
                    while j < 3 && i + j < value.len() && (b'0'..=b'7').contains(&value[i + j]) {
                        j += 1;
                    }
                    if j == 3 && value[i] > b'3' {
                        j -= 1;
                    }
                    let n = value[i..i + j]
                        .iter()
                        .fold(0u32, |n, d| n * 8 + (d - b'0') as u32);
                    out.push(n as u8);
                    i += j - 1;
                }
                c => out.push(c),
            }
        } else {
            out.push(value[i]);
        }
        i += 1;
    }
    out
}

/// The leading digits of a reply code, as C atoi reads them
fn atoi(s: &str) -> u16 {
    s.bytes()
        .take_while(u8::is_ascii_digit)
        .fold(0u16, |n, d| n * 10 + (d - b'0') as u16)
}

/// HMAC-SHA256 under `key` of cookie | client nonce | server nonce
/// (ComputeResponse, torcontrol.cpp:570-579)
fn compute_response(key: &str, cookie: &[u8], client_nonce: &[u8], server_nonce: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("any key length");
    mac.update(cookie);
    mac.update(client_nonce);
    mac.update(server_nonce);
    mac.finalize().into_bytes().to_vec()
}

/// One control connection: commands out, replies in
struct Conn {
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
    writer: tokio::net::tcp::OwnedWriteHalf,
}

impl Conn {
    /// Send a command and wait for its reply; asynchronous (6xx) replies are
    /// skipped. `None` when the connection ends.
    async fn command(&mut self, cmd: &str) -> Option<Reply> {
        let mut out = cmd.as_bytes().to_vec();
        out.extend_from_slice(b"\r\n");
        self.writer.write_all(&out).await.ok()?;
        self.reply().await
    }

    /// The next synchronous reply (TorControlConnection::readcb,
    /// torcontrol.cpp:157-184): lines shorter than 4 bytes are skipped
    async fn reply(&mut self) -> Option<Reply> {
        let mut message = Reply::default();
        loop {
            let mut line = Vec::new();
            let n = (&mut self.reader)
                .take(MAX_LINE_LENGTH as u64 + 1)
                .read_until(b'\n', &mut line)
                .await
                .ok()?;
            if n == 0 {
                return None;
            }
            if !line.ends_with(b"\n") {
                info!("tor: Disconnecting because MAX_LINE_LENGTH exceeded");
                return None;
            }
            line.pop();
            if line.ends_with(b"\r") {
                line.pop();
            }
            if line.len() < 4 {
                continue;
            }
            let s = String::from_utf8_lossy(&line).into_owned();
            message.code = atoi(&s[..3]);
            message.lines.push(s[4..].to_string());
            if line[3] == b' ' {
                if message.code >= 600 {
                    message = Reply::default();
                    continue;
                }
                return Some(message);
            }
        }
    }
}

/// Run the controller for the life of the node (TorControlThread,
/// torcontrol.cpp:742-747). A target that is not a numeric address is never
/// tried again; otherwise a lost connection is retried after 1 s, then each
/// wait half again as long (torcontrol.cpp:698-714).
pub fn spawn(control: TorControl, peers: Arc<PeerManager>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(target) = control.target.parse::<SocketAddr>() else {
            info!("tor: Error parsing socket address {}", control.target);
            info!(
                "tor: Initiating connection to Tor control port {} failed",
                control.target
            );
            return;
        };
        let mut private_key = std::fs::read(&control.private_key_file)
            .ok()
            .map(|k| String::from_utf8_lossy(&k).into_owned());
        if private_key.is_some() {
            debug!(
                "tor: Reading cached private key from {}",
                control.private_key_file.display()
            );
        }
        let mut reconnect_timeout = RECONNECT_TIMEOUT_START;
        loop {
            if let Ok(stream) = TcpStream::connect(target).await {
                debug!("tor: Successfully connected!");
                reconnect_timeout = RECONNECT_TIMEOUT_START;
                let (r, w) = stream.into_split();
                let mut conn = Conn {
                    reader: BufReader::new(r),
                    writer: w,
                };
                let service = session(&mut conn, &control, &peers, &mut private_key).await;
                // Stop advertising the service once disconnected
                if let Some(service) = service {
                    peers.local_addresses().remove(&service);
                }
            } else {
                debug!("tor: Error connecting to Tor control socket");
            }
            debug!(
                "tor: Not connected to Tor control port {}, trying to reconnect",
                control.target
            );
            tokio::time::sleep(Duration::from_millis((reconnect_timeout * 1000.0) as u64)).await;
            reconnect_timeout *= RECONNECT_TIMEOUT_EXP;
        }
    })
}

/// One connection's exchange, until it ends; the service advertised, if any
async fn session(
    conn: &mut Conn,
    control: &TorControl,
    peers: &Arc<PeerManager>,
    private_key: &mut Option<String>,
) -> Option<SocketAddr> {
    let reply = conn.command("PROTOCOLINFO 1").await?;
    // With no way to authenticate nothing more is sent; the connection
    // stays open until Tor closes it
    let Some(auth) = authenticate(conn, control, &reply).await? else {
        return wait_closed(conn, None).await;
    };
    if auth.code != 250 {
        info!("tor: Authentication failed");
        return wait_closed(conn, None).await;
    }
    debug!("tor: Authentication successful");
    // Tor runs: onion peers go through its SOCKS port unless -onion says
    // otherwise (torcontrol.cpp:531-539)
    if control.set_onion_proxy {
        peers.set_tor_proxy(Some(Proxy {
            addr: SocketAddr::from(([127, 0, 0, 1], 9050)),
            randomize_credentials: false,
        }));
    }
    let port = peers.local_addresses().port();
    let key = private_key
        .clone()
        .unwrap_or_else(|| "NEW:RSA1024".to_string());
    let reply = conn
        .command(&format!("ADD_ONION {key} Port={port},127.0.0.1:{port}"))
        .await?;
    let mut service = None;
    if reply.code == 250 {
        debug!("tor: ADD_ONION successful");
        let mut service_id = String::new();
        for line in &reply.lines {
            let m = parse_reply_mapping(line);
            if let Some(id) = m.get("ServiceID") {
                service_id = id.clone();
            }
            if let Some(k) = m.get("PrivateKey") {
                *private_key = Some(k.clone());
            }
        }
        match crate::local::onion_from_name(&format!("{service_id}.onion")) {
            Some(ip) if !service_id.is_empty() => {
                let addr = SocketAddr::new(ip, port);
                info!("tor: Got service ID {service_id}, advertising service {service_id}.onion:{port}");
                let key = private_key.clone().unwrap_or_default();
                match std::fs::write(&control.private_key_file, key) {
                    Ok(()) => debug!(
                        "tor: Cached service private key to {}",
                        control.private_key_file.display()
                    ),
                    Err(_) => info!(
                        "tor: Error writing service private key to {}",
                        control.private_key_file.display()
                    ),
                }
                // AddLocal(service, LOCAL_MANUAL), which marks onion reachable
                if peers.local_addresses().add(addr, LOCAL_MANUAL) {
                    peers.set_tor_reachable(true);
                }
                service = Some(addr);
            }
            _ => {
                info!("tor: Error parsing ADD_ONION parameters:");
                for line in &reply.lines {
                    info!("    {line}");
                }
            }
        }
    } else if reply.code == 510 {
        info!("tor: Add onion failed with unrecognized command (You probably need to upgrade Tor)");
    } else {
        info!("tor: Add onion failed; error code {}", reply.code);
    }
    // The service lasts as long as the connection
    wait_closed(conn, service).await
}

/// Choose and run the authentication (protocolinfo_cb, torcontrol.cpp:616-688):
/// `-torpassword` with HASHEDPASSWORD, else NULL, else SAFECOOKIE. The outer
/// `None` is a lost connection; the inner one, no authentication to try.
async fn authenticate(
    conn: &mut Conn,
    control: &TorControl,
    reply: &Reply,
) -> Option<Option<Reply>> {
    if reply.code != 250 {
        info!("tor: Requesting protocol info failed");
        return Some(None);
    }
    let mut methods = std::collections::BTreeSet::new();
    let mut cookie_file = String::new();
    for line in &reply.lines {
        let (kind, rest) = split_reply_line(line);
        let m = parse_reply_mapping(rest);
        if kind == "AUTH" {
            if let Some(v) = m.get("METHODS") {
                methods = v.split(',').map(str::to_string).collect();
            }
            if let Some(v) = m.get("COOKIEFILE") {
                cookie_file = v.clone();
            }
        } else if kind == "VERSION" {
            if let Some(v) = m.get("Tor") {
                debug!("tor: Connected to Tor version {v}");
            }
        }
    }
    if !control.password.is_empty() {
        if methods.contains("HASHEDPASSWORD") {
            debug!("tor: Using HASHEDPASSWORD authentication");
            let password = control.password.replace('"', "\\\"");
            return conn
                .command(&format!("AUTHENTICATE \"{password}\""))
                .await
                .map(Some);
        }
        info!("tor: Password provided with -torpassword, but HASHEDPASSWORD authentication is not available");
        return Some(None);
    }
    if methods.contains("NULL") {
        debug!("tor: Using NULL authentication");
        return conn.command("AUTHENTICATE").await.map(Some);
    }
    if methods.contains("SAFECOOKIE") {
        debug!("tor: Using SAFECOOKIE authentication, reading cookie authentication from {cookie_file}");
        let cookie = match std::fs::read(&cookie_file) {
            Ok(c) if c.len() == TOR_COOKIE_SIZE => c,
            Ok(_) => {
                info!(
                    "tor: Authentication cookie {cookie_file} is not exactly {TOR_COOKIE_SIZE} bytes, as is required by the spec"
                );
                return Some(None);
            }
            Err(_) => {
                info!("tor: Authentication cookie {cookie_file} could not be opened (check permissions)");
                return Some(None);
            }
        };
        let client_nonce: [u8; TOR_NONCE_SIZE] = rand::random();
        let reply = conn
            .command(&format!(
                "AUTHCHALLENGE SAFECOOKIE {}",
                hex::encode(client_nonce)
            ))
            .await?;
        if reply.code != 250 {
            info!("tor: SAFECOOKIE authentication challenge failed");
            return Some(None);
        }
        let (kind, rest) = split_reply_line(reply.lines.first().map_or("", |l| l.as_str()));
        if kind != "AUTHCHALLENGE" {
            info!("tor: Invalid reply to AUTHCHALLENGE");
            return Some(None);
        }
        let m = parse_reply_mapping(rest);
        if m.is_empty() {
            info!("tor: Error parsing AUTHCHALLENGE parameters: {rest}");
            return Some(None);
        }
        let parse = |k: &str| {
            m.get(k)
                .and_then(|v| hex::decode(v).ok())
                .unwrap_or_default()
        };
        let (server_hash, server_nonce) = (parse("SERVERHASH"), parse("SERVERNONCE"));
        if server_nonce.len() != 32 {
            info!("tor: ServerNonce is not 32 bytes, as required by spec");
            return Some(None);
        }
        let computed = compute_response(TOR_SAFE_SERVERKEY, &cookie, &client_nonce, &server_nonce);
        if computed != server_hash {
            info!(
                "tor: ServerHash {} does not match expected ServerHash {}",
                hex::encode(&server_hash),
                hex::encode(&computed)
            );
            return Some(None);
        }
        let client = compute_response(TOR_SAFE_CLIENTKEY, &cookie, &client_nonce, &server_nonce);
        return conn
            .command(&format!("AUTHENTICATE {}", hex::encode(client)))
            .await
            .map(Some);
    }
    if methods.contains("HASHEDPASSWORD") {
        info!("tor: The only supported authentication mechanism left is password, but no password provided with -torpassword");
    } else {
        info!("tor: No supported authentication method");
    }
    Some(None)
}

/// Keep the connection until Tor closes it, then give back `service`
async fn wait_closed(conn: &mut Conn, service: Option<SocketAddr>) -> Option<SocketAddr> {
    while conn.reply().await.is_some() {
        debug!("tor: Received unexpected sync reply");
    }
    service
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reply_mapping_as_core_parses_it() {
        let m = parse_reply_mapping(
            r#"METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/home/x/.tor/control_auth_cookie""#,
        );
        assert_eq!(m["METHODS"], "COOKIE,SAFECOOKIE");
        assert_eq!(m["COOKIEFILE"], "/home/x/.tor/control_auth_cookie");
        let m = parse_reply_mapping(r#"Foo="Eq\"\\uals" Bar=a=b"#);
        assert_eq!(m["Foo"], "Eq\"\\uals");
        assert_eq!(m["Bar"], "a=b");
        // Octal escapes: up to three digits, two when the first is over 3
        let m = parse_reply_mapping(r#"A="\101\1012\477" B="\n\t\r\x""#);
        assert_eq!(m["A"].as_bytes(), b"AA2'7");
        assert_eq!(m["B"], "\n\t\rx");
        // Unterminated: nothing
        assert!(parse_reply_mapping(r#"A="open"#).is_empty());
        assert!(parse_reply_mapping("NOVALUE").is_empty());
        // The rest after a bare word is OptArguments
        assert_eq!(parse_reply_mapping("A=1 rest of it").len(), 1);
    }

    #[test]
    fn split_reply_line_as_core() {
        assert_eq!(
            split_reply_line("AUTH METHODS=NULL"),
            ("AUTH", "METHODS=NULL")
        );
        assert_eq!(split_reply_line("OK"), ("OK", ""));
    }

    /// One fake control port on 127.0.0.1 for one session: answers each
    /// command from `answer` and records the commands
    async fn fake_control(
        answer: impl Fn(&str) -> String + Send + 'static,
    ) -> (SocketAddr, Arc<parking_lot::Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<parking_lot::Mutex<Vec<String>>> = Default::default();
        let record = seen.clone();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut lines = BufReader::new(r).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                record.lock().push(line.clone());
                let out = answer(&line);
                if w.write_all(out.as_bytes()).await.is_err() {
                    break;
                }
            }
        });
        (addr, seen)
    }

    fn peers(port: u16) -> Arc<PeerManager> {
        let pm = PeerManager::new(Default::default());
        pm.set_local_addresses(crate::local::LocalAddresses::new(true, false, port));
        pm
    }

    async fn wait_for(pm: &PeerManager, want: impl Fn(&PeerManager) -> bool) {
        for _ in 0..100 {
            if want(pm) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    const ID: &str = "abcdefghij234567";

    fn add_onion_reply() -> String {
        format!("250-ServiceID={ID}\r\n250-PrivateKey=RSA1024:not-a-real-key\r\n250 OK\r\n")
    }

    #[tokio::test]
    async fn safecookie_authenticates_and_adds_the_onion_service() {
        let dir = tempfile::tempdir().unwrap();
        let cookie_file = dir.path().join("control_auth_cookie");
        let cookie = [7u8; 32];
        std::fs::write(&cookie_file, cookie).unwrap();
        let server_nonce = [9u8; 32];
        let cookie_path = cookie_file.display().to_string();
        let client_nonce: Arc<parking_lot::Mutex<Vec<u8>>> = Default::default();
        let nonce = client_nonce.clone();
        let (addr, seen) = fake_control(move |line| {
            if line == "PROTOCOLINFO 1" {
                format!(
                    "250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE=\"{cookie_path}\"\r\n250-VERSION Tor=\"0.4.8\"\r\n250 OK\r\n"
                )
            } else if let Some(n) = line.strip_prefix("AUTHCHALLENGE SAFECOOKIE ") {
                *nonce.lock() = hex::decode(n).unwrap();
                let hash = compute_response(TOR_SAFE_SERVERKEY, &cookie, &nonce.lock(), &server_nonce);
                format!(
                    "250 AUTHCHALLENGE SERVERHASH={} SERVERNONCE={}\r\n",
                    hex::encode(hash),
                    hex::encode(server_nonce)
                )
            } else if let Some(h) = line.strip_prefix("AUTHENTICATE ") {
                let want = compute_response(TOR_SAFE_CLIENTKEY, &cookie, &nonce.lock(), &server_nonce);
                if h == hex::encode(want) {
                    "250 OK\r\n".into()
                } else {
                    "515 Authentication failed\r\n".into()
                }
            } else if line.starts_with("ADD_ONION ") {
                add_onion_reply()
            } else {
                "510 Unrecognized command\r\n".into()
            }
        })
        .await;
        let pm = peers(51476);
        let key_file = dir.path().join("onion_private_key");
        let task = spawn(
            TorControl {
                target: addr.to_string(),
                password: String::new(),
                private_key_file: key_file.clone(),
                set_onion_proxy: true,
            },
            pm.clone(),
        );
        wait_for(&pm, |pm| !pm.local_addresses().list().is_empty()).await;
        task.abort();
        let got = seen.lock().clone();
        assert_eq!(got[0], "PROTOCOLINFO 1");
        assert_eq!(client_nonce.lock().len(), 32);
        assert!(got[2].starts_with("AUTHENTICATE "), "{got:?}");
        assert_eq!(got[3], "ADD_ONION NEW:RSA1024 Port=51476,127.0.0.1:51476");
        let local = pm.local_addresses().list();
        assert_eq!(local.len(), 1);
        assert_eq!(
            crate::local::onion_name(&local[0].address).unwrap(),
            format!("{ID}.onion")
        );
        assert_eq!((local[0].port, local[0].score), (51476, LOCAL_MANUAL));
        assert!(pm.tor_reachable());
        assert_eq!(
            pm.tor_proxy()
                .map(|p| (p.addr.to_string(), p.randomize_credentials)),
            Some(("127.0.0.1:9050".to_string(), false))
        );
        assert_eq!(
            std::fs::read_to_string(key_file).unwrap(),
            "RSA1024:not-a-real-key"
        );
    }

    #[tokio::test]
    async fn saved_key_is_reused_and_onion_proxy_left_alone_with_onion_set() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("onion_private_key");
        std::fs::write(&key_file, "RSA1024:saved-fake-key").unwrap();
        let (addr, seen) = fake_control(|line| {
            if line == "PROTOCOLINFO 1" {
                "250-AUTH METHODS=NULL\r\n250 OK\r\n".into()
            } else if line == "AUTHENTICATE" {
                "250 OK\r\n".into()
            } else {
                format!("250-ServiceID={ID}\r\n250 OK\r\n")
            }
        })
        .await;
        let pm = peers(51476);
        let task = spawn(
            TorControl {
                target: addr.to_string(),
                password: String::new(),
                private_key_file: key_file.clone(),
                set_onion_proxy: false,
            },
            pm.clone(),
        );
        wait_for(&pm, |pm| !pm.local_addresses().list().is_empty()).await;
        task.abort();
        assert_eq!(
            seen.lock().clone(),
            [
                "PROTOCOLINFO 1",
                "AUTHENTICATE",
                "ADD_ONION RSA1024:saved-fake-key Port=51476,127.0.0.1:51476"
            ]
        );
        assert!(pm.tor_proxy().is_none());
    }

    #[tokio::test]
    async fn password_needs_hashedpassword_and_is_quoted() {
        for (methods, want) in [
            (
                "HASHEDPASSWORD",
                Some(r#"AUTHENTICATE "dummy-\"not\"-a-password""#),
            ),
            ("NULL", None),
        ] {
            let (addr, seen) = fake_control(move |line| {
                if line == "PROTOCOLINFO 1" {
                    format!("250-AUTH METHODS={methods}\r\n250 OK\r\n")
                } else {
                    "515 Authentication failed\r\n".into()
                }
            })
            .await;
            let dir = tempfile::tempdir().unwrap();
            let pm = peers(51476);
            let task = spawn(
                TorControl {
                    target: addr.to_string(),
                    password: r#"dummy-"not"-a-password"#.to_string(),
                    private_key_file: dir.path().join("onion_private_key"),
                    set_onion_proxy: true,
                },
                pm.clone(),
            );
            tokio::time::sleep(Duration::from_millis(500)).await;
            task.abort();
            let got = seen.lock().clone();
            assert_eq!(got.first().map(String::as_str), Some("PROTOCOLINFO 1"));
            assert_eq!(got.get(1).map(String::as_str), want, "{methods}");
            assert_eq!(got.len(), 1 + want.is_some() as usize, "{got:?}");
            // Refused: no onion proxy, no service
            assert!(pm.tor_proxy().is_none());
            assert!(pm.local_addresses().list().is_empty());
        }
    }

    #[tokio::test]
    async fn service_is_dropped_when_the_connection_ends() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (s, _) = listener.accept().await.unwrap();
            let (r, mut w) = s.into_split();
            let mut lines = BufReader::new(r).lines();
            for out in [
                "250-AUTH METHODS=NULL\r\n250 OK\r\n".to_string(),
                "250 OK\r\n".to_string(),
                add_onion_reply(),
            ] {
                lines.next_line().await.unwrap();
                w.write_all(out.as_bytes()).await.unwrap();
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        });
        let dir = tempfile::tempdir().unwrap();
        let pm = peers(51476);
        let task = spawn(
            TorControl {
                target: addr.to_string(),
                password: String::new(),
                private_key_file: dir.path().join("onion_private_key"),
                set_onion_proxy: true,
            },
            pm.clone(),
        );
        wait_for(&pm, |pm| !pm.local_addresses().list().is_empty()).await;
        assert_eq!(pm.local_addresses().list().len(), 1);
        wait_for(&pm, |pm| pm.local_addresses().list().is_empty()).await;
        task.abort();
        assert!(pm.local_addresses().list().is_empty());
    }
}
