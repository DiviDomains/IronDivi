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

//! Minimal SOCKS5 client (RFC 1928) for outbound P2P connections through `-proxy`
//!
//! What C++ `Socks5()` (netbase.cpp:316-420) uses: CONNECT, with no
//! authentication or, under `-proxyrandomize`, a username and password made at
//! random for each connection (RFC 1929), so Tor gives each connection a
//! circuit of its own. The destination always goes as a name (ATYP 3): the
//! address as text, an onion address as its `.onion` name, or a host name.

use crate::error::NetworkError;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USER_PASS: u8 = 0x02;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

fn proxy_error(msg: impl Into<String>) -> NetworkError {
    NetworkError::Connection(format!("SOCKS5 proxy: {}", msg.into()))
}

/// Text of a SOCKS5 reply code (RFC 1928 section 6)
fn reply_text(code: u8) -> &'static str {
    match code {
        0x01 => "general failure",
        0x02 => "connection not allowed",
        0x03 => "network unreachable",
        0x04 => "host unreachable",
        0x05 => "connection refused",
        0x06 => "TTL expired",
        0x07 => "command not supported",
        0x08 => "address type not supported",
        _ => "unknown error",
    }
}

/// A SOCKS5 proxy and whether each connection through it gets credentials of
/// its own (Divi Core's `proxyType`, netbase.h:179-188)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Proxy {
    pub addr: SocketAddr,
    pub randomize_credentials: bool,
}

/// Divi Core's random credentials for one connection: two `rand32()` values
/// written with `%i` (netbase.cpp:604-608), so they may be negative
pub fn random_credentials() -> (String, String) {
    (
        (rand::random::<u32>() as i32).to_string(),
        (rand::random::<u32>() as i32).to_string(),
    )
}

/// The text Divi Core gives the proxy for `ip` (CNetAddr::ToStringIP): the
/// `.onion` name of an onion address, else the address as text
pub fn destination_name(ip: &std::net::IpAddr) -> String {
    crate::local::onion_name(ip).unwrap_or_else(|| ip.to_string())
}

/// Connect to `proxy` and ask it to open a TCP connection to `target`.
/// On success the returned stream is a plain byte pipe to `target`.
pub async fn connect(proxy: Proxy, target: SocketAddr) -> Result<TcpStream, NetworkError> {
    connect_to_name(proxy, &destination_name(&target.ip()), target.port()).await
}

/// Connect to `proxy` and ask it to open a TCP connection to `host:port`, the
/// proxy resolving `host` (Divi Core's ConnectThroughProxy, netbase.cpp:594-617)
pub async fn connect_to_name(
    proxy: Proxy,
    host: &str,
    port: u16,
) -> Result<TcpStream, NetworkError> {
    let mut stream = TcpStream::connect(proxy.addr)
        .await
        .map_err(|e| proxy_error(format!("cannot reach proxy {}: {}", proxy.addr, e)))?;
    let credentials = proxy.randomize_credentials.then(random_credentials);
    handshake(&mut stream, host, port, credentials.as_ref()).await?;
    Ok(stream)
}

/// Run the SOCKS5 greeting, the username/password exchange when the proxy
/// asks for it and `credentials` are given, and the CONNECT request for
/// `host:port` on an open stream to the proxy
pub async fn handshake(
    stream: &mut TcpStream,
    host: &str,
    port: u16,
    credentials: Option<&(String, String)>,
) -> Result<(), NetworkError> {
    if host.len() > 255 {
        return Err(proxy_error("hostname too long"));
    }
    let greeting: &[u8] = if credentials.is_some() {
        &[SOCKS_VERSION, 2, METHOD_NO_AUTH, METHOD_USER_PASS]
    } else {
        &[SOCKS_VERSION, 1, METHOD_NO_AUTH]
    };
    stream.write_all(greeting).await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != SOCKS_VERSION {
        return Err(proxy_error("proxy is not a SOCKS5 proxy"));
    }
    match (choice[1], credentials) {
        (METHOD_USER_PASS, Some((user, password))) => {
            if user.len() > 255 || password.len() > 255 {
                return Err(proxy_error("username or password too long"));
            }
            let mut auth = vec![0x01, user.len() as u8];
            auth.extend_from_slice(user.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream.write_all(&auth).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status != [0x01, 0x00] {
                return Err(proxy_error("proxy authentication unsuccessful"));
            }
        }
        (METHOD_NO_AUTH, _) => {}
        _ => return Err(proxy_error("proxy requested wrong authentication method")),
    }

    let mut request = vec![
        SOCKS_VERSION,
        CMD_CONNECT,
        0x00,
        ATYP_DOMAIN,
        host.len() as u8,
    ];
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != SOCKS_VERSION {
        return Err(proxy_error("malformed reply"));
    }
    if reply[1] != 0x00 {
        return Err(proxy_error(format!(
            "connect to {}:{} failed: {}",
            host,
            port,
            reply_text(reply[1])
        )));
    }
    // Skip the bound address the proxy reports
    let addr_len = match reply[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            len[0] as usize
        }
        _ => return Err(proxy_error("malformed reply address")),
    };
    let mut bound = vec![0u8; addr_len + 2];
    stream.read_exact(&mut bound).await?;
    Ok(())
}

/// A one-connection SOCKS5 stub for tests: accepts, records the CONNECT target, opens
/// it and pipes bytes both ways.
#[cfg(test)]
pub(crate) mod stub {
    use super::*;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    /// Start the stub on a free localhost port; returns its address and the list of
    /// CONNECT targets it has served, as `host:port` text
    pub async fn start() -> (SocketAddr, Arc<parking_lot::Mutex<Vec<String>>>) {
        let (addr, seen, _) = start_recording().await;
        (addr, seen)
    }

    /// The methods a client offered and the credentials it sent, per connection
    pub type Greetings = Arc<parking_lot::Mutex<Vec<(Vec<u8>, Option<(String, String)>)>>>;

    /// As `start`, also recording each greeting; the stub picks username and
    /// password authentication whenever it is offered
    pub async fn start_recording() -> (SocketAddr, Arc<parking_lot::Mutex<Vec<String>>>, Greetings)
    {
        run(None).await
    }

    /// As `start_recording`, but every CONNECT, whatever its target, opens
    /// `to` (so a test can name a routable target and stay on the host)
    pub async fn start_redirecting(
        to: SocketAddr,
    ) -> (SocketAddr, Arc<parking_lot::Mutex<Vec<String>>>, Greetings) {
        run(Some(to)).await
    }

    async fn run(
        redirect: Option<SocketAddr>,
    ) -> (SocketAddr, Arc<parking_lot::Mutex<Vec<String>>>, Greetings) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let greetings: Greetings = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen_task = Arc::clone(&seen);
        let greetings_task = Arc::clone(&greetings);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let seen = Arc::clone(&seen_task);
                let greetings = Arc::clone(&greetings_task);
                tokio::spawn(async move {
                    let mut greet = [0u8; 2];
                    client.read_exact(&mut greet).await.unwrap();
                    let mut methods = vec![0u8; greet[1] as usize];
                    client.read_exact(&mut methods).await.unwrap();
                    assert_eq!(greet[0], SOCKS_VERSION);
                    assert!(methods.contains(&METHOD_NO_AUTH));
                    let mut credentials = None;
                    if methods.contains(&METHOD_USER_PASS) {
                        client
                            .write_all(&[SOCKS_VERSION, METHOD_USER_PASS])
                            .await
                            .unwrap();
                        let mut head = [0u8; 2];
                        client.read_exact(&mut head).await.unwrap();
                        let mut user = vec![0u8; head[1] as usize];
                        client.read_exact(&mut user).await.unwrap();
                        let mut len = [0u8; 1];
                        client.read_exact(&mut len).await.unwrap();
                        let mut password = vec![0u8; len[0] as usize];
                        client.read_exact(&mut password).await.unwrap();
                        credentials = Some((
                            String::from_utf8(user).unwrap(),
                            String::from_utf8(password).unwrap(),
                        ));
                        client.write_all(&[0x01, 0x00]).await.unwrap();
                    } else {
                        client
                            .write_all(&[SOCKS_VERSION, METHOD_NO_AUTH])
                            .await
                            .unwrap();
                    }
                    greetings.lock().push((methods, credentials));
                    let mut head = [0u8; 4];
                    client.read_exact(&mut head).await.unwrap();
                    assert_eq!(head[..3], [SOCKS_VERSION, CMD_CONNECT, 0]);
                    let (host, port) = match head[3] {
                        ATYP_IPV4 => {
                            let mut b = [0u8; 6];
                            client.read_exact(&mut b).await.unwrap();
                            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                            (ip.to_string(), u16::from_be_bytes([b[4], b[5]]))
                        }
                        ATYP_IPV6 => {
                            let mut b = [0u8; 18];
                            client.read_exact(&mut b).await.unwrap();
                            let mut ip = [0u8; 16];
                            ip.copy_from_slice(&b[..16]);
                            (
                                std::net::Ipv6Addr::from(ip).to_string(),
                                u16::from_be_bytes([b[16], b[17]]),
                            )
                        }
                        ATYP_DOMAIN => {
                            let mut len = [0u8; 1];
                            client.read_exact(&mut len).await.unwrap();
                            let mut b = vec![0u8; len[0] as usize + 2];
                            client.read_exact(&mut b).await.unwrap();
                            let n = len[0] as usize;
                            (
                                String::from_utf8(b[..n].to_vec()).unwrap(),
                                u16::from_be_bytes([b[n], b[n + 1]]),
                            )
                        }
                        other => panic!("unexpected address type {other}"),
                    };
                    seen.lock().push(format!("{host}:{port}"));
                    let target = match host.parse::<std::net::IpAddr>() {
                        Ok(ip) => SocketAddr::new(ip, port),
                        // a name: only a redirecting stub can open it
                        Err(_) => redirect.unwrap_or_else(|| ([127, 0, 0, 1], 1).into()),
                    };
                    match TcpStream::connect(redirect.unwrap_or(target)).await {
                        Ok(mut upstream) => {
                            client
                                .write_all(&[SOCKS_VERSION, 0, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                                .await
                                .unwrap();
                            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                        }
                        Err(_) => {
                            let _ = client
                                .write_all(&[SOCKS_VERSION, 5, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
                                .await;
                        }
                    }
                });
            }
        });
        (addr, seen, greetings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(addr: SocketAddr) -> Proxy {
        Proxy {
            addr,
            randomize_credentials: false,
        }
    }

    #[tokio::test]
    async fn test_connect_through_stub_reaches_target() {
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        let (proxy, seen) = stub::start().await;
        let accept = tokio::spawn(async move {
            let (mut s, from) = target_listener.accept().await.unwrap();
            let mut buf = [0u8; 5];
            s.read_exact(&mut buf).await.unwrap();
            (buf, from)
        });
        let mut stream = connect(plain(proxy), target).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let (buf, _) = accept.await.unwrap();
        assert_eq!(&buf, b"hello");
        // The target goes as a name: the address as text (netbase.cpp:383-386)
        assert_eq!(*seen.lock(), vec![target.to_string()]);
    }

    #[tokio::test]
    async fn test_refused_target_is_an_error() {
        let closed = SocketAddr::from(([127, 0, 0, 1], divi_test_support::free_port()));
        let (proxy, _) = stub::start().await;
        let err = connect(plain(proxy), closed).await.unwrap_err().to_string();
        assert!(err.contains("connection refused"), "{err}");
    }

    #[tokio::test]
    async fn test_unreachable_proxy_is_an_error() {
        let closed = SocketAddr::from(([127, 0, 0, 1], divi_test_support::free_port()));
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = connect(plain(closed), target)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot reach proxy"), "{err}");
    }

    /// With -proxyrandomize (the default) each connection offers no
    /// authentication and username/password, and sends two decimal numbers of
    /// its own (netbase.cpp:322-332, :604-608); without, only no authentication
    #[tokio::test]
    async fn randomized_credentials_differ_per_connection() {
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = target_listener.local_addr().unwrap();
        tokio::spawn(async move { while target_listener.accept().await.is_ok() {} });
        let (proxy, _, greetings) = stub::start_recording().await;
        let randomized = Proxy {
            addr: proxy,
            randomize_credentials: true,
        };
        connect(randomized, target).await.unwrap();
        connect(randomized, target).await.unwrap();
        connect(plain(proxy), target).await.unwrap();
        let got = greetings.lock().clone();
        assert_eq!(got.len(), 3);
        for (methods, credentials) in &got[..2] {
            assert_eq!(methods, &vec![METHOD_NO_AUTH, METHOD_USER_PASS]);
            let (user, password) = credentials.as_ref().unwrap();
            assert!(user.parse::<i32>().is_ok() && password.parse::<i32>().is_ok());
        }
        assert_ne!(got[0].1, got[1].1);
        assert_eq!(got[2], (vec![METHOD_NO_AUTH], None));
    }
}
