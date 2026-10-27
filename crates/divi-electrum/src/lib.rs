// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! IronDivi's optional Electrum protocol server, on with `-electrum` (plain
//! TCP) and `-electrumtls` (TLS). Light wallets such as BasicSwap's
//! `--light` mode use it in place of a local node. The design is in
//! docs/electrum-server.md.

pub mod backend;
pub mod session;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use divi_rpc::blockchain::MempoolProvider;
use divi_rpc::RpcServer;
use divi_storage::Chain;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Semaphore};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

pub use backend::Backend;

/// Most connections served at once, over TCP and TLS together
const MAX_CONNECTIONS: usize = 1000;

/// The TLS listener: where it binds and its PEM certificate chain and key
#[derive(Debug, Clone)]
pub struct TlsConfig {
    pub bind: SocketAddr,
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Clone)]
pub struct ElectrumConfig {
    pub tcp: Option<SocketAddr>,
    pub tls: Option<TlsConfig>,
    pub banner: String,
}

/// The listeners, bound and ready before the node starts its other work, so
/// a taken port fails startup
pub struct Prepared {
    tcp: Option<std::net::TcpListener>,
    tls: Option<(std::net::TcpListener, TlsAcceptor)>,
    banner: Arc<String>,
}

fn bind(addr: SocketAddr) -> anyhow::Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::bind(addr)
        .with_context(|| format!("electrum: cannot listen on {addr}"))?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

fn tls_acceptor(config: &TlsConfig) -> anyhow::Result<TlsAcceptor> {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};

    let certs = CertificateDer::pem_file_iter(&config.cert)
        .with_context(|| format!("electrum: cannot read {}", config.cert.display()))?
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("electrum: bad certificate in {}", config.cert.display()))?;
    if certs.is_empty() {
        anyhow::bail!("electrum: no certificate in {}", config.cert.display());
    }
    let key = PrivateKeyDer::from_pem_file(&config.key)
        .with_context(|| format!("electrum: cannot read a key from {}", config.key.display()))?;
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .context("electrum: the TLS certificate and key do not match")?;
    Ok(TlsAcceptor::from(Arc::new(server)))
}

/// Binds the listeners and loads the TLS certificate
pub fn prepare(config: ElectrumConfig) -> anyhow::Result<Prepared> {
    let tcp = config.tcp.map(bind).transpose()?;
    let tls = match &config.tls {
        Some(tls) => Some((bind(tls.bind)?, tls_acceptor(tls)?)),
        None => None,
    };
    Ok(Prepared {
        tcp,
        tls,
        banner: Arc::new(config.banner),
    })
}

impl Prepared {
    /// The bound TCP address, if any
    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp.as_ref().and_then(|l| l.local_addr().ok())
    }

    /// The bound TLS address, if any
    pub fn tls_addr(&self) -> Option<SocketAddr> {
        self.tls.as_ref().and_then(|(l, _)| l.local_addr().ok())
    }

    /// Fills the scripthash index if needed, then serves until `shutdown`
    pub fn spawn(
        self,
        chain: Arc<Chain>,
        mempool: Arc<dyn MempoolProvider>,
        rpc: Arc<RpcServer>,
        shutdown: broadcast::Receiver<()>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            if let Some(index) = chain.search_index().cloned() {
                match tokio::task::spawn_blocking(move || index.backfill_script_hashes()).await {
                    Ok(Ok(0)) => {}
                    Ok(Ok(n)) => tracing::info!("electrum: indexed {n} script hashes"),
                    Ok(Err(e)) => tracing::error!("electrum: script hash backfill failed: {e}"),
                    Err(e) => tracing::error!("electrum: script hash backfill failed: {e}"),
                }
            }
            let backend = Arc::new(Backend::new(chain, mempool, rpc));
            let limit = Arc::new(Semaphore::new(MAX_CONNECTIONS));
            let mut tasks = Vec::new();
            if let Some(listener) = self.tcp {
                match TcpListener::from_std(listener) {
                    Ok(listener) => {
                        tracing::info!(
                            "electrum: listening on {:?} (tcp)",
                            listener.local_addr().ok()
                        );
                        tasks.push(tokio::spawn(accept_loop(
                            listener,
                            None,
                            backend.clone(),
                            self.banner.clone(),
                            limit.clone(),
                            shutdown.resubscribe(),
                        )));
                    }
                    Err(e) => tracing::error!("electrum: tcp listener failed: {e}"),
                }
            }
            if let Some((listener, acceptor)) = self.tls {
                match TcpListener::from_std(listener) {
                    Ok(listener) => {
                        tracing::info!(
                            "electrum: listening on {:?} (tls)",
                            listener.local_addr().ok()
                        );
                        tasks.push(tokio::spawn(accept_loop(
                            listener,
                            Some(acceptor),
                            backend.clone(),
                            self.banner.clone(),
                            limit.clone(),
                            shutdown.resubscribe(),
                        )));
                    }
                    Err(e) => tracing::error!("electrum: tls listener failed: {e}"),
                }
            }
            for task in tasks {
                let _ = task.await;
            }
        })
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls: Option<TlsAcceptor>,
    backend: Arc<Backend>,
    banner: Arc<String>,
    limit: Arc<Semaphore>,
    mut shutdown: broadcast::Receiver<()>,
) {
    loop {
        let accepted = tokio::select! {
            _ = shutdown.recv() => return,
            accepted = listener.accept() => accepted,
        };
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::debug!("electrum: accept failed: {e}");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };
        let Ok(permit) = limit.clone().try_acquire_owned() else {
            tracing::debug!("electrum: refusing {peer}: too many connections");
            continue;
        };
        let _ = stream.set_nodelay(true);
        let backend = backend.clone();
        let banner = banner.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tls {
                None => session::run(stream, backend, banner).await,
                Some(acceptor) => {
                    let handshake = tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        acceptor.accept(stream),
                    )
                    .await;
                    match handshake {
                        Ok(Ok(stream)) => session::run(stream, backend, banner).await,
                        Ok(Err(e)) => tracing::debug!("electrum: tls handshake with {peer}: {e}"),
                        Err(_) => tracing::debug!("electrum: tls handshake with {peer} timed out"),
                    }
                }
            }
        });
    }
}
