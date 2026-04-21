// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! dcQUIC cross-version compatibility test endpoint.
//!
//! This binary can act as a server or client for testing wire compatibility
//! between different versions of s2n-quic-dc. It uses the real PSK handshake
//! path so that two independently-built binaries can communicate over the wire.
//!
//! Usage:
//!   dcquic-compat server --protocol tcp
//!   dcquic-compat client --protocol tcp --addr [::1]:5555 --handshake-addr [::1]:6666 --scenario echo

use s2n_quic::provider::tls;
use s2n_quic_core::{crypto::tls::testing::certificates, time::StdClock};
use s2n_quic_dc::{
    path::secret::{stateless_reset::Signer, Map},
    psk,
    stream::{client::tokio::Client, server::tokio::Server, socket::Protocol},
    testing::NoopSubscriber,
};
use std::{env, io, net::SocketAddr, process, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  dcquic-compat server --protocol <tcp|udp>");
    eprintln!("  dcquic-compat client --protocol <tcp|udp> --addr <ADDR> --handshake-addr <ADDR> --scenario <echo|large-echo|bidirectional>");
    process::exit(2);
}

fn parse_flag(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1).cloned())
}

fn parse_protocol(args: &[String]) -> Protocol {
    match parse_flag(args, "--protocol").as_deref().unwrap_or("tcp") {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        other => {
            eprintln!("unknown protocol: {other}");
            usage();
        }
    }
}

// -- TLS provider using test certificates --

#[derive(Clone)]
struct TestTlsProvider;

impl tls::Provider for TestTlsProvider {
    type Server = tls::default::Server;
    type Client = tls::default::Client;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn start_server(self) -> Result<Self::Server, Self::Error> {
        Ok(tls::default::Server::builder()
            .with_application_protocols(["h3"].iter())?
            .with_certificate(certificates::CERT_PEM, certificates::KEY_PEM)?
            .build()?)
    }

    fn start_client(self) -> Result<Self::Client, Self::Error> {
        Ok(tls::default::Client::builder()
            .with_application_protocols(["h3"].iter())?
            .with_certificate(certificates::CERT_PEM)?
            .build()?)
    }
}

fn make_map(capacity: usize) -> Map {
    Map::new(
        Signer::new(b"compat-test"),
        capacity,
        false,
        StdClock::default(),
        NoopSubscriber,
    )
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let result = match args[1].as_str() {
        "server" => {
            let protocol = parse_protocol(&args);
            run_server(protocol).await
        }
        "client" => {
            let protocol = parse_protocol(&args);
            let addr: SocketAddr = parse_flag(&args, "--addr")
                .unwrap_or_else(|| {
                    eprintln!("--addr is required");
                    usage();
                })
                .parse()
                .expect("invalid --addr");
            let handshake_addr: SocketAddr = parse_flag(&args, "--handshake-addr")
                .unwrap_or_else(|| {
                    eprintln!("--handshake-addr is required");
                    usage();
                })
                .parse()
                .expect("invalid --handshake-addr");
            let scenario = parse_flag(&args, "--scenario").unwrap_or_else(|| "echo".to_string());
            run_client(protocol, addr, handshake_addr, &scenario).await
        }
        _ => usage(),
    };

    if let Err(e) = result {
        eprintln!("ERROR: {e}");
        process::exit(1);
    }
}

async fn run_server(protocol: Protocol) -> io::Result<()> {
    let map = make_map(50_000);

    let server_psk = psk::server::Provider::builder()
        .start(
            "[::1]:0".parse().unwrap(),
            TestTlsProvider,
            NoopSubscriber,
            map.clone(),
        )
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let server = Server::<psk::server::Provider, NoopSubscriber>::builder()
        .with_address("[::1]:0".parse().unwrap())
        .with_protocol(protocol)
        .with_workers(1.try_into().unwrap())
        .build(server_psk.clone(), NoopSubscriber)?;

    let acceptor_addr = server.acceptor_addr()?;
    let handshake_addr = server.handshake_addr()?;

    // Machine-readable output for the test harness
    println!("ACCEPTOR={acceptor_addr}");
    println!("HANDSHAKE={handshake_addr}");
    println!("READY");

    // Accept connections in a loop until the process is killed
    loop {
        let (mut stream, peer_addr) = server.accept().await?;
        eprintln!("server: accepted connection from {peer_addr}");

        tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Err(e) = stream.read_to_end(&mut buf).await {
                eprintln!("server: read error: {e}");
                return;
            }
            eprintln!("server: received {} bytes", buf.len());

            if let Err(e) = stream.write_all(&buf).await {
                eprintln!("server: write error: {e}");
                return;
            }
            if let Err(e) = stream.shutdown().await {
                eprintln!("server: shutdown error: {e}");
                return;
            }
            eprintln!("server: echoed {} bytes", buf.len());
        });
    }
}

async fn run_client(
    protocol: Protocol,
    acceptor_addr: SocketAddr,
    handshake_addr: SocketAddr,
    scenario: &str,
) -> io::Result<()> {
    let map = make_map(50_000);

    let client_psk = psk::client::Provider::builder()
        .start(
            "[::]:0".parse().unwrap(),
            map,
            TestTlsProvider,
            NoopSubscriber,
            "localhost".into(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let client = Client::<psk::client::Provider, NoopSubscriber>::builder()
        .with_default_protocol(protocol)
        .build(client_psk, NoopSubscriber)?;

    let server_name = "localhost".into();

    match scenario {
        "echo" => {
            let payload = b"hello from cross-version compat test";
            let mut stream = client
                .connect(handshake_addr, acceptor_addr, server_name)
                .await?;

            stream.write_all(payload).await?;
            stream.shutdown().await?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;

            assert_eq!(
                &response,
                payload,
                "echo mismatch: expected {} bytes, got {}",
                payload.len(),
                response.len()
            );
            println!("SUCCESS scenario=echo bytes={}", payload.len());
        }
        "large-echo" => {
            // ~1MB payload
            let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
            let mut stream = client
                .connect(handshake_addr, acceptor_addr, server_name)
                .await?;

            stream.write_all(&payload).await?;
            stream.shutdown().await?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;

            assert_eq!(response.len(), payload.len(), "large echo size mismatch");
            assert_eq!(response, payload, "large echo content mismatch");
            println!("SUCCESS scenario=large-echo bytes={}", payload.len());
        }
        "bidirectional" => {
            let client_payload = b"client-to-server-bidirectional";
            let mut stream = client
                .connect(handshake_addr, acceptor_addr, server_name)
                .await?;

            stream.write_all(client_payload).await?;
            stream.shutdown().await?;

            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;

            assert_eq!(&response, client_payload, "bidirectional echo mismatch");
            println!(
                "SUCCESS scenario=bidirectional bytes={}",
                client_payload.len()
            );
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown scenario: {other}"),
            ));
        }
    }

    // Give time for graceful cleanup
    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}
