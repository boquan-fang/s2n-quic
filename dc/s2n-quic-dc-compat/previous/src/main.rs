// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! dcQUIC cross-version compatibility test endpoint (previous version).
//!
//! Built against an older s2n-quic-dc from crates.io. Communicates over the
//! wire with the current version binary to verify protocol compatibility.

use s2n_quic_core::time::StdClock;
use s2n_quic_dc::{
    path::secret::{stateless_reset::Signer, Map},
    psk,
    stream::{client::tokio::Client, server::tokio::Server, socket::Protocol},
    testing::{NoopSubscriber, TestTlsProvider},
};
use std::{env, io, net::SocketAddr, process, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// No-op callback required by the v0.69.0 PSK client builder API
fn query_event(_conn: &mut s2n_quic::Connection, _duration: Duration) {}

fn usage() -> ! {
    eprintln!("Usage:");
    eprintln!("  dcquic-compat-previous server --protocol <tcp|udp>");
    eprintln!("  dcquic-compat-previous client --protocol <tcp|udp> --addr <ADDR> --handshake-addr <ADDR> --scenario <echo|large-echo|bidirectional>");
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

fn make_map() -> Map {
    Map::new(
        Signer::new(b"compat-test"),
        50_000,
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
        "server" => run_server(parse_protocol(&args)).await,
        "client" => {
            let protocol = parse_protocol(&args);
            let addr: SocketAddr = parse_flag(&args, "--addr")
                .unwrap_or_else(|| {
                    eprintln!("--addr required");
                    usage();
                })
                .parse()
                .expect("invalid --addr");
            let hs_addr: SocketAddr = parse_flag(&args, "--handshake-addr")
                .unwrap_or_else(|| {
                    eprintln!("--handshake-addr required");
                    usage();
                })
                .parse()
                .expect("invalid --handshake-addr");
            let scenario = parse_flag(&args, "--scenario").unwrap_or_else(|| "echo".into());
            run_client(protocol, addr, hs_addr, &scenario).await
        }
        _ => usage(),
    };

    if let Err(e) = result {
        eprintln!("ERROR: {e}");
        process::exit(1);
    }
}

async fn run_server(protocol: Protocol) -> io::Result<()> {
    let server_psk = psk::server::Provider::builder()
        .start(
            "[::1]:0".parse().unwrap(),
            TestTlsProvider {},
            NoopSubscriber,
            make_map(),
        )
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let server = Server::<psk::server::Provider, NoopSubscriber>::builder()
        .with_address("[::1]:0".parse().unwrap())
        .with_protocol(protocol)
        .with_workers(1.try_into().unwrap())
        .build(server_psk, NoopSubscriber)?;

    println!("ACCEPTOR={}", server.acceptor_addr()?);
    println!("HANDSHAKE={}", server.handshake_addr()?);
    println!("READY");

    loop {
        let (mut stream, _peer) = server.accept().await?;
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let _ = stream.read_to_end(&mut buf).await;
            let _ = stream.write_all(&buf).await;
            let _ = stream.shutdown().await;
        });
    }
}

async fn run_client(
    protocol: Protocol,
    acceptor_addr: SocketAddr,
    handshake_addr: SocketAddr,
    scenario: &str,
) -> io::Result<()> {
    let client_psk = psk::client::Provider::builder()
        .start(
            "[::]:0".parse().unwrap(),
            make_map(),
            TestTlsProvider {},
            NoopSubscriber,
            query_event,
            "localhost".into(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

    let client = Client::<psk::client::Provider, NoopSubscriber>::builder()
        .with_default_protocol(protocol)
        .build(client_psk, NoopSubscriber)?;

    match scenario {
        "echo" => {
            let payload = b"hello from cross-version compat test";
            let mut stream = client
                .connect(handshake_addr, acceptor_addr, "localhost".into())
                .await?;
            stream.write_all(payload).await?;
            stream.shutdown().await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            assert_eq!(&response, payload, "echo mismatch");
            println!("SUCCESS scenario=echo bytes={}", payload.len());
        }
        "large-echo" => {
            let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
            let mut stream = client
                .connect(handshake_addr, acceptor_addr, "localhost".into())
                .await?;
            stream.write_all(&payload).await?;
            stream.shutdown().await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            assert_eq!(response, payload, "large echo mismatch");
            println!("SUCCESS scenario=large-echo bytes={}", payload.len());
        }
        "bidirectional" => {
            let payload = b"client-to-server-bidirectional";
            let mut stream = client
                .connect(handshake_addr, acceptor_addr, "localhost".into())
                .await?;
            stream.write_all(payload).await?;
            stream.shutdown().await?;
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await?;
            assert_eq!(&response, payload, "bidirectional echo mismatch");
            println!("SUCCESS scenario=bidirectional bytes={}", payload.len());
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown scenario: {other}"),
            ))
        }
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    Ok(())
}
