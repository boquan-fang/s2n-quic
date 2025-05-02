use futures::future::join_all;
use s2n_quic::{client::Connect, Client};
use std::{error::Error, net::SocketAddr};

/// NOTE: this certificate is to be used for demonstration purposes only!
pub static CERT_PEM: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../quic/s2n-quic-core/certs/cert.pem"
));

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    loop {
        let mut fut = vec![];
        for _ in 0..100 {
            fut.push(tokio::spawn(run()));
        }
        join_all(fut).await;
    }
    Ok(())
}

async fn run() {
    let client = Client::builder()
        .with_tls(CERT_PEM)
        .unwrap()
        .with_io("0.0.0.0:0")
        .unwrap()
        .start()
        .unwrap();
    let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
    let connect = Connect::new(addr).with_server_name("localhost");
    let mut connection = client.connect(connect).await.unwrap();

    // Explicitly close the connection with a timeout
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        connection.close(0u8.into()),
    )
    .await;

    // Explicitly drop the client to ensure all resources are cleaned up
    drop(client);
}
