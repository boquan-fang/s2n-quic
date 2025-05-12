// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::{client::Connect, Client, Server};
use std::{error::Error, net::SocketAddr};

async fn server_run() -> Result<(), Box<dyn Error + Send + Sync>> {
    println!("Starting server!");
    let mut server = Server::builder()
        .with_tls((certificates::CERT_PEM, certificates::KEY_PEM))
        .unwrap()
        .with_io("127.0.0.1:4433")
        .unwrap()
        .with_event(crate::provider::event::tracing::Subscriber::default())
        .unwrap()
        .start()
        .unwrap();

    if let Some(mut connection) = server.accept().await {
        tokio::spawn(async move {
            while let Ok(Some(mut stream)) = connection.accept_bidirectional_stream().await {
                tokio::spawn(async move {
                    while let Ok(Some(data)) = stream.receive().await {
                        let _ = data;
                    }
                });
            }
        });
    }

    Ok(())
}

async fn client_run() -> Result<(), Box<dyn Error + Send + Sync>> {
    let client = Client::builder()
        .with_tls(certificates::CERT_PEM)
        .unwrap()
        .with_event(crate::provider::event::tracing::Subscriber::default())
        .unwrap()
        .with_io("0.0.0.0:0")
        .unwrap()
        .start()
        .unwrap();
    let addr: SocketAddr = "127.0.0.1:4433".parse()?;
    let connect = Connect::new(addr).with_server_name("localhost");
    let _ = client.connect(connect).await?;
    println!("Client successfully connect to the server!");

    Ok(())
}

#[tokio::test]
async fn endpoint_drop_test() -> Result<(), Box<dyn Error + Send + Sync>> {
    tokio::spawn(async { server_run().await });
    tokio::spawn(async { client_run().await });
    println!("Start sleeping for five seconds!");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    Ok(())
}
