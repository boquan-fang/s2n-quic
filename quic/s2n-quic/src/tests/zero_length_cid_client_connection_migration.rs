// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::provider::tls::default::{self as tls};
use s2n_quic_core::inet::ExplicitCongestionNotification::*;

#[test]
fn zero_length_cid_client_connection_migration_test() {
    let model = Model::default();

    // TODO:: Create event subscribers

    test(model, |handle| {
        // Set up a s2n-quic server
        let server = tls::Server::builder()
            .with_application_protocols(["h3"].iter())
            .unwrap()
            .with_certificate(certificates::CERT_PEM, certificates::KEY_PEM)
            .unwrap()
            .build()
            .unwrap();

        let server = Server::builder()
            .with_io(handle.builder().build()?)?
            .with_tls(server)?
            .with_event(tracing_events())?
            .with_random(Random::with_seed(456))?
            .start()?;

        let server_addr = start_server(server)?;

        // Set up a Cloudflare Quiche client
        let mut client_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        client_config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();
        client_config.verify_peer(false);

        // create a zero-length Source CID
        let scid = quiche::ConnectionId::default();

        let socket = handle.builder().build()?.socket();

        // Create a QUIC connection and initiate handshake.
        let mut conn = quiche::connect(
            Some(&"localhost"),
            &scid,
            socket.local_addr().unwrap(),
            server_addr,
            &mut client_config,
        )
        .unwrap();

        // Check if the client is using zero-length CID
        assert_eq!(conn.source_id().len(), 0);

        // Establish handshake from the client to the server
        let mut out = [0; 1350];

        loop {
            let (write, send_info) = match conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    break;
                }

                Err(_) => {
                    panic!("Send failed!");
                }
            };

            socket
                .send_to(send_info.to, NotEct, out[..write].to_vec())
                .unwrap();
        }

        // TODO:: Client perform connection migration

        Ok(())
    })
    .unwrap();
}
