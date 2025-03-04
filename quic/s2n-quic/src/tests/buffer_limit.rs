// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[test]
#[cfg(feature = "s2n-quic-tls")]
fn buffer_limit_test() {
    use super::*;
    use crate::provider::tls::s2n_tls;
    let model = Model::default();
    test(model, |handle| {
        // Client should be able to send a large ClientHello
        let client_tls = s2n_tls::Client::builder()
            .with_certificate(certificates::CERT_PEM)?
            .build()?;

        // Server and Client set up for TLS handshake
        let server = Server::builder()
            .with_io(handle.builder().build()?)?
            .with_tls(SERVER_CERTS)?
            .with_event(tracing_events())?
            .with_random(Random::with_seed(456))?
            .start()?;
        let client = Client::builder()
            .with_io(handle.builder().build()?)?
            .with_tls(client_tls)?
            .with_event(tracing_events())?
            .with_random(Random::with_seed(456))?
            .start()?;

        let addr = start_server(server)?;
        // Assert that the TLS handshake by the client failed due to buffering
        start_client(client, addr, Data::new(10000))?;
        Ok(addr)
    })
    .unwrap();
}
