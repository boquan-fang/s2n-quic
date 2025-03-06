// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::provider::tls::default::{self as tls, security};

static MAX_NUM_FAKE_PROTOCOL: usize = 1600;

#[test]
fn buffer_limit_test() {
    let model = Model::default();
    let policy = &security::Policy::from_version("default_tls13").unwrap();

    test(model, |handle| {
        let server = tls::Server::from_loader({
            let mut builder = tls::config::Config::builder();
            builder
                .enable_quic()?
                .set_application_protocol_preference(["h3"])?
                .set_security_policy(policy)?
                .load_pem(
                    certificates::CERT_PEM.as_bytes(),
                    certificates::KEY_PEM.as_bytes(),
                )?;

            builder.build()?
        });

        // Server and Client set up for TLS handshake
        let server = Server::builder()
            .with_io(handle.builder().build()?)?
            .with_tls(server)?
            .with_event(tracing_events())?
            .with_random(Random::with_seed(456))?
            .start()?;

        // Fill application_layer_protocol_negotiation extension in ClientHello
        let mut application_protocols: Vec<String> = Vec::new();
        application_protocols.push("h3".to_string());
        for _ in 0..MAX_NUM_FAKE_PROTOCOL {
            application_protocols.push("fake-protocol".to_string());
        }

        let client = tls::Client::from_loader({
            let mut builder = tls::config::Config::builder();
            builder
                .enable_quic()?
                .set_application_protocol_preference(application_protocols)?
                .set_security_policy(policy)?
                .trust_pem(certificates::CERT_PEM.as_bytes())?;

            builder.build()?
        });

        let client = Client::builder()
            .with_io(handle.builder().build()?)?
            .with_tls(client)?
            .with_event(tracing_events())?
            .with_random(Random::with_seed(456))?
            .start()?;

        let addr = start_server(server)?;
        // Assert that the TLS handshake by the client failed due to buffering
        start_client(client, addr, Data::new(1000))?;
        Ok(addr)
    })
    .unwrap();
}
