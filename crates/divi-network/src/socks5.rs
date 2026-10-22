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
//! Only what C++ `Socks5()` (netbase.cpp) uses: no authentication, CONNECT, and an
//! IPv4 or IPv6 destination.

use crate::error::NetworkError;
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
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

/// Connect to `proxy` and ask it to open a TCP connection to `target`.
/// On success the returned stream is a plain byte pipe to `target`.
pub async fn connect(proxy: SocketAddr, target: SocketAddr) -> Result<TcpStream, NetworkError> {
    let mut stream = TcpStream::connect(proxy)
        .await
        .map_err(|e| proxy_error(format!("cannot reach proxy {}: {}", proxy, e)))?;
    handshake(&mut stream, target).await?;
    Ok(stream)
}

/// Run the SOCKS5 greeting and CONNECT request on an open stream to the proxy
pub async fn handshake(stream: &mut TcpStream, target: SocketAddr) -> Result<(), NetworkError> {
    stream
        .write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH])
        .await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != SOCKS_VERSION {
        return Err(proxy_error("proxy is not a SOCKS5 proxy"));
    }
    if choice[1] != METHOD_NO_AUTH {
        return Err(proxy_error("proxy requires authentication"));
    }

    let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0x00];
    match target {
        SocketAddr::V4(a) => {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&a.ip().octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != SOCKS_VERSION {
        return Err(proxy_error("malformed reply"));
    }
    if reply[1] != 0x00 {
        return Err(proxy_error(format!(
            "connect to {} failed: {}",
            target,
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
    /// CONNECT targets it has served
    pub async fn start() -> (SocketAddr, Arc<parking_lot::Mutex<Vec<SocketAddr>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let seen_task = Arc::clone(&seen);
        tokio::spawn(async move {
            while let Ok((mut client, _)) = listener.accept().await {
                let seen = Arc::clone(&seen_task);
                tokio::spawn(async move {
                    let mut greet = [0u8; 2];
                    client.read_exact(&mut greet).await.unwrap();
                    let mut methods = vec![0u8; greet[1] as usize];
                    client.read_exact(&mut methods).await.unwrap();
                    assert_eq!(greet[0], SOCKS_VERSION);
                    assert!(methods.contains(&METHOD_NO_AUTH));
                    client
                        .write_all(&[SOCKS_VERSION, METHOD_NO_AUTH])
                        .await
                        .unwrap();
                    let mut head = [0u8; 4];
                    client.read_exact(&mut head).await.unwrap();
                    assert_eq!(head[..3], [SOCKS_VERSION, CMD_CONNECT, 0]);
                    let target: SocketAddr = match head[3] {
                        ATYP_IPV4 => {
                            let mut b = [0u8; 6];
                            client.read_exact(&mut b).await.unwrap();
                            let ip = std::net::Ipv4Addr::new(b[0], b[1], b[2], b[3]);
                            (ip, u16::from_be_bytes([b[4], b[5]])).into()
                        }
                        ATYP_IPV6 => {
                            let mut b = [0u8; 18];
                            client.read_exact(&mut b).await.unwrap();
                            let mut ip = [0u8; 16];
                            ip.copy_from_slice(&b[..16]);
                            (
                                std::net::Ipv6Addr::from(ip),
                                u16::from_be_bytes([b[16], b[17]]),
                            )
                                .into()
                        }
                        other => panic!("unexpected address type {other}"),
                    };
                    seen.lock().push(target);
                    match TcpStream::connect(target).await {
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
        (addr, seen)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut stream = connect(proxy, target).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let (buf, _) = accept.await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(*seen.lock(), vec![target]);
    }

    #[tokio::test]
    async fn test_refused_target_is_an_error() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let (proxy, _) = stub::start().await;
        let err = connect(proxy, closed).await.unwrap_err().to_string();
        assert!(err.contains("connection refused"), "{err}");
    }

    #[tokio::test]
    async fn test_unreachable_proxy_is_an_error() {
        let closed = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let target: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let err = connect(closed, target).await.unwrap_err().to_string();
        assert!(err.contains("cannot reach proxy"), "{err}");
    }
}
