// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cross-version testing infrastructure.
//!
//! When the `S2N_CROSS_VERSION` environment variable is set, the shared test
//! helpers (`server()`, `client()`, etc.) automatically swap one side to the
//! previous published release of s2n-quic. This allows the entire test suite
//! to run cross-version tests without modifying individual test files.
//!
//! Supported values:
//! - `client_ahead`: current client, previous-version server
//! - `server_ahead`: current server, previous-version client
//!
//! When unset (or set to any other value), all helpers use the current version.

use s2n_quic::provider::io::testing::{Handle, Model, Result};
use s2n_quic_core_prev::crypto::tls::testing::certificates as prev_certificates;
use std::net::SocketAddr;

/// The cross-version configuration, read once from the environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionConfig {
    /// Both sides use current code (default).
    SameVersion,
    /// Current client, previous-version server.
    ClientAhead,
    /// Current server, previous-version client.
    ServerAhead,
}

impl VersionConfig {
    /// Read the configuration from the `S2N_CROSS_VERSION` env var.
    pub fn from_env() -> Self {
        match std::env::var("S2N_CROSS_VERSION").as_deref() {
            Ok("client_ahead") => Self::ClientAhead,
            Ok("server_ahead") => Self::ServerAhead,
            _ => Self::SameVersion,
        }
    }

    pub fn should_use_prev_server(self) -> bool {
        self == Self::ClientAhead
    }

    pub fn should_use_prev_client(self) -> bool {
        self == Self::ServerAhead
    }
}

pub static PREV_SERVER_CERTS: (&str, &str) =
    (prev_certificates::CERT_PEM, prev_certificates::KEY_PEM);

type PrevHandle = s2n_quic_prev::provider::io::testing::Handle;

/// Convert a current-version Handle into a prev-version Handle.
///
/// # Safety
///
/// Both `Handle` types are structurally identical. They both contain:
/// - `executor: bach::executor::Handle` (same bach crate, same type)
/// - `buffers: network::Buffers` (identical source, identical layout)
///
/// We clone the current handle first (to properly increment Arc refcounts),
/// then transmute the clone into the prev version's Handle type.
fn to_prev_handle(handle: &Handle) -> PrevHandle {
    const _: () = {
        assert!(std::mem::size_of::<Handle>() == std::mem::size_of::<PrevHandle>());
        assert!(std::mem::align_of::<Handle>() == std::mem::align_of::<PrevHandle>());
    };

    let cloned = handle.clone();
    unsafe {
        let cloned = std::mem::ManuallyDrop::new(cloned);
        std::mem::transmute_copy(&*cloned)
    }
}

// Implement the previous version's provider traits on the existing Random type.
// This avoids duplicating the struct — we just add the prev version's trait impls.
use crate::Random;

impl s2n_quic_prev::provider::random::Provider for Random {
    type Generator = Self;
    type Error = core::convert::Infallible;

    fn start(self) -> core::result::Result<Self::Generator, Self::Error> {
        Ok(self)
    }
}

impl s2n_quic_prev::provider::random::Generator for Random {
    fn public_random_fill(&mut self, dest: &mut [u8]) {
        rand::rand_core::Rng::fill_bytes(self, dest);
    }

    fn private_random_fill(&mut self, dest: &mut [u8]) {
        rand::rand_core::Rng::fill_bytes(self, dest);
    }
}

// ── prev-version endpoint helpers ──────────────────────────────────────

/// Build and start a server using the previous version of s2n-quic.
pub fn prev_server(handle: &Handle, _network_env: Model) -> Result<SocketAddr> {
    let server = prev_build_server(handle)?;
    prev_start_server(server)
}

/// Build a server using the previous version of s2n-quic.
pub fn prev_build_server(handle: &Handle) -> Result<s2n_quic_prev::Server> {
    let prev_handle = to_prev_handle(handle);
    Ok(s2n_quic_prev::Server::builder()
        .with_io(prev_handle.builder().build().unwrap())?
        .with_tls(PREV_SERVER_CERTS)?
        .with_random(Random::with_seed(123))?
        .start()?)
}

/// Start a previously-built prev-version server, accepting connections and echoing data.
pub fn prev_start_server(mut server: s2n_quic_prev::Server) -> Result<SocketAddr> {
    use s2n_quic_prev::provider::io::testing::spawn;
    use s2n_quic_prev::stream::PeerStream;

    let server_addr = server.local_addr()?;

    spawn(async move {
        while let Some(mut connection) = server.accept().await {
            spawn(async move {
                while let Ok(Some(stream)) = connection.accept().await {
                    match stream {
                        PeerStream::Receive(mut stream) => {
                            spawn(async move { while let Ok(Some(_)) = stream.receive().await {} });
                        }
                        PeerStream::Bidirectional(mut stream) => {
                            spawn(async move {
                                while let Ok(Some(chunk)) = stream.receive().await {
                                    let _ = stream.send(chunk).await;
                                }
                            });
                        }
                    }
                }
            });
        }
    });

    Ok(server_addr)
}

/// Build and start a client using the previous version of s2n-quic.
pub fn prev_client(
    handle: &Handle,
    server_addr: SocketAddr,
    _network_env: Model,
    _with_blocklist: bool,
) -> Result {
    let client = prev_build_client(handle)?;
    prev_start_client(client, server_addr)
}

/// Build a client using the previous version of s2n-quic.
pub fn prev_build_client(handle: &Handle) -> Result<s2n_quic_prev::Client> {
    let prev_handle = to_prev_handle(handle);
    Ok(s2n_quic_prev::Client::builder()
        .with_io(prev_handle.builder().build().unwrap())?
        .with_tls(prev_certificates::CERT_PEM)?
        .with_random(Random::with_seed(123))?
        .start()?)
}

/// Start a previously-built prev-version client that connects, sends data, and verifies echo.
pub fn prev_start_client(client: s2n_quic_prev::Client, server_addr: SocketAddr) -> Result {
    use s2n_quic_core_prev::stream::testing::Data;
    use s2n_quic_prev::client::Connect;
    use s2n_quic_prev::provider::io::testing::primary;

    let data = Data::new(10_000);

    primary::spawn(async move {
        let connect = Connect::new(server_addr).with_server_name("localhost");
        let mut connection = client.connect(connect).await.unwrap();

        let stream = connection.open_bidirectional_stream().await.unwrap();
        let (mut recv, mut send) = stream.split();

        let mut send_data = data;
        let mut recv_data = data;

        primary::spawn(async move {
            while let Some(chunk) = recv.receive().await.unwrap() {
                recv_data.receive(&[chunk]);
            }
            assert!(recv_data.is_finished());
        });

        while let Some(chunk) = send_data.send_one(usize::MAX) {
            send.send(chunk).await.unwrap();
        }
    });

    Ok(())
}
