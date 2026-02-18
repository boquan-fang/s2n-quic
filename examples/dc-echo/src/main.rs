// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! dcQUIC Echo Example
//!
//! This example demonstrates a complete dcQUIC client-server echo flow:
//! 1. A PSK handshake server and data acceptor server are started
//! 2. A PSK handshake client connects, performing the QUIC-based key exchange
//! 3. A dcQUIC stream is established and the client sends "Hello, dcQUIC!"
//! 4. The server echoes the data back
//!
//! ## Running with packet capture and TLS key logging:
//!
//! Terminal 1 (capture all loopback traffic):
//!   sudo tcpdump -i lo -s 0 -w dc_echo.pcap
//!
//! Terminal 2 (run the example with key logging):
//!   SSLKEYLOGFILE=keys.log cargo run --manifest-path examples/dc-echo/Cargo.toml
//!
//! Terminal 1: Ctrl+C to stop capture
//!
//! Then open dc_echo.pcap in Wireshark with keys.log:
//!   Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename → keys.log

use s2n_quic::provider::tls::default as tls_provider;
use s2n_quic_core::crypto::tls::testing::certificates;
use s2n_quic_core::time::StdClock;
use s2n_quic_dc::{
    event,
    path::secret::{stateless_reset::Signer, Map},
    psk::{client, server},
    stream::{
        client::tokio::Client as StreamClient, server::tokio::Server as StreamServer,
        socket::Protocol,
    },
};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const HANDSHAKE_ADDR: &str = "127.0.0.1:4433";
const ACCEPTOR_ADDR: &str = "127.0.0.1:4444";
const SERVER_NAME: &str = "localhost";

/// Minimal event subscriber (no-op) for dcQUIC events
#[derive(Clone, Default)]
struct NoopSubscriber;

impl event::Subscriber for NoopSubscriber {
    type ConnectionContext = ();
    fn create_connection_context(
        &self,
        _meta: &event::api::ConnectionMeta,
        _info: &event::api::ConnectionInfo,
    ) -> Self::ConnectionContext {
    }
}

impl s2n_quic_core::event::Subscriber for NoopSubscriber {
    type ConnectionContext = ();
    fn create_connection_context(
        &mut self,
        _meta: &s2n_quic_core::event::api::ConnectionMeta,
        _info: &s2n_quic_core::event::api::ConnectionInfo,
    ) -> Self::ConnectionContext {
    }
}

fn build_tls_server() -> tls_provider::Server {
    let mut builder = tls_provider::Server::builder()
        .with_application_protocols(["h3"].iter())
        .unwrap()
        .with_certificate(certificates::CERT_PEM, certificates::KEY_PEM)
        .unwrap();

    // Enable key logging if SSLKEYLOGFILE is set
    builder = builder.with_key_logging().unwrap();

    builder.build().unwrap()
}

fn build_tls_client() -> tls_provider::Client {
    let mut builder = tls_provider::Client::builder()
        .with_application_protocols(["h3"].iter())
        .unwrap()
        .with_certificate(certificates::CERT_PEM)
        .unwrap();

    // Enable key logging if SSLKEYLOGFILE is set
    builder = builder.with_key_logging().unwrap();

    builder.build().unwrap()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let format = tracing_subscriber::fmt::format()
        .with_level(false) // don't include levels in formatted output
        .with_ansi(false)
        .without_time()
        .compact(); // Use a less verbose output format.

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .event_format(format)
        .init();

    let subscriber = NoopSubscriber;

    // ==========================================
    // 1. Start the PSK handshake server
    // ==========================================
    let server_map = Map::new(
        Signer::new(b"default"),
        50_000,
        // false,
        StdClock::default(),
        subscriber.clone(),
    );

    let tls_server = build_tls_server();
    let handshake_addr = HANDSHAKE_ADDR.parse().unwrap();

    let psk_server = server::Provider::builder()
        .with_event_subscriber(s2n_quic::provider::event::tracing::Subscriber::default())
        .start(
            handshake_addr,
            tls_server,
            // subscriber.clone(),
            s2n_quic::provider::event::tracing::Subscriber::default(),
            server_map.clone(),
        )
        .await?;

    let actual_handshake_addr = psk_server.local_addr();
    // eprintln!("[server] PSK handshake server listening on {actual_handshake_addr}");

    // ==========================================
    // 2. Start the data acceptor server (dcQUIC stream server)
    // ==========================================
    let acceptor_addr = ACCEPTOR_ADDR.parse().unwrap();
    let stream_server = StreamServer::<server::Provider, NoopSubscriber>::builder()
        .with_address(acceptor_addr)
        .with_protocol(Protocol::Udp)
        .with_workers(1.try_into().unwrap())
        .build(psk_server.clone(), subscriber.clone())?;

    let actual_acceptor_addr = stream_server.acceptor_addr()?;
    // eprintln!("[server] Data acceptor listening on {actual_acceptor_addr}");

    // ==========================================
    // 3. Start the PSK handshake client
    // ==========================================
    let client_map = Map::new(
        Signer::new(b"default"),
        50_000,
        // false,
        StdClock::default(),
        subscriber.clone(),
    );

    let tls_client = build_tls_client();
    let server_name: s2n_quic::server::Name = SERVER_NAME.into();

    let psk_client = client::Provider::builder()
        .with_success_jitter(Duration::ZERO)
        .with_event_subscriber(s2n_quic::provider::event::tracing::Subscriber::default())
        .start(
            "0.0.0.0:0".parse().unwrap(),
            client_map,
            tls_client,
            // subscriber.clone(),
            s2n_quic::provider::event::tracing::Subscriber::default(),
            server_name.clone(),
        )?;

    // eprintln!("[client] PSK handshake client started");

    // ==========================================
    // 4. Create the stream client
    // ==========================================
    let stream_client = StreamClient::<client::Provider, NoopSubscriber>::builder()
        .with_default_protocol(Protocol::Udp)
        .build(psk_client, subscriber.clone())?;

    // eprintln!("[client] Stream client ready");

    // ==========================================
    // 5. Spawn the echo server task
    // ==========================================
    let server_handle = tokio::spawn(async move {
        eprintln!("[server] Waiting for connections...");
        match stream_server.accept().await {
            Ok((mut stream, peer_addr)) => {
                eprintln!("[server] Accepted connection from {peer_addr}");

                // Echo: read data and send it back
                let mut buf = vec![0u8; 4096];
                match stream.read(&mut buf).await {
                    Ok(n) if n > 0 => {
                        let data = &buf[..n];
                        eprintln!(
                            "[server] Received {} bytes: {:?}",
                            n,
                            String::from_utf8_lossy(data)
                        );

                        // Echo the data back
                        if let Err(e) = stream.write_all(data).await {
                            eprintln!("[server] Error writing echo: {e}");
                        }
                        if let Err(e) = stream.shutdown().await {
                            eprintln!("[server] Error shutting down: {e}");
                        }
                        eprintln!("[server] Echoed {n} bytes back");
                    }
                    Ok(_) => eprintln!("[server] Connection closed (0 bytes)"),
                    Err(e) => eprintln!("[server] Read error: {e}"),
                }
            }
            Err(e) => eprintln!("[server] Accept error: {e}"),
        }
    });

    // Give the server a moment to be ready
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ==========================================
    // 6. Client: connect, send, receive echo
    // ==========================================
    eprintln!(
        // "[client] Connecting to handshake={actual_handshake_addr} acceptor={actual_acceptor_addr}"
    );

    let mut stream = stream_client
        .connect(actual_handshake_addr, actual_acceptor_addr, server_name)
        .await?;

    eprintln!(
        "[client] Connected! local={} peer={}",
        stream.local_addr()?,
        stream.peer_addr()?
    );

    // Send a message
    let message = b"Hello, dcQUIC!";
    stream.write_all(message).await?;
    stream.shutdown().await?;
    eprintln!("[client] Sent: {:?}", String::from_utf8_lossy(message));

    // Read the echo
    let mut response = vec![0u8; 4096];
    let n = stream.read(&mut response).await?;
    eprintln!(
        "[client] Received echo: {:?}",
        String::from_utf8_lossy(&response[..n])
    );

    assert_eq!(&response[..n], message, "Echo mismatch!");
    // eprintln!("[client] ✓ Echo verified!");

    // Wait for server to finish
    let _ = tokio::time::timeout(Duration::from_secs(5), server_handle).await;

    eprintln!("\nDone! If you captured packets, check the pcap file.");
    if std::env::var("SSLKEYLOGFILE").is_ok() {
        eprintln!(
            "TLS keys were logged — use them in Wireshark to decrypt QUIC handshake traffic."
        );
    } else {
        eprintln!(
            "Tip: Set SSLKEYLOGFILE=keys.log to enable TLS key logging for Wireshark decryption."
        );
    }

    Ok(())
}
