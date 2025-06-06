// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::provider::{
    connection_id,
    tls::default::{self as tls},
};
struct ZeroLengthIdFormat;

impl connection_id::Generator for ZeroLengthIdFormat {
    fn generate(
        &mut self,
        _connection_info: &s2n_quic_core::connection::id::ConnectionInfo,
    ) -> s2n_quic_core::connection::LocalId {
        let id = [];
        connection_id::LocalId::try_from_bytes(&id[..]).unwrap()
    }
}

impl connection_id::Validator for ZeroLengthIdFormat {
    fn validate(
        &self,
        _connection_info: &s2n_quic_core::connection::id::ConnectionInfo,
        _buffer: &[u8],
    ) -> Option<usize> {
        Some(0)
    }
}

#[test]
fn zero_length_cid_client_test() {
    let model = Model::default();

    test(model, |handle| {
        let server = tls::Server::builder()
            .with_certificate(certificates::CERT_PEM, certificates::KEY_PEM)
            .unwrap()
            .build()
            .unwrap();

        let server = Server::builder()
            .with_io(handle.builder().build()?)?
            .with_tls(server)?
            .with_event(tracing_events())?
            .with_connection_id(connection_id::Default::default())?
            .with_random(Random::with_seed(456))?
            .start()?;

        let client = tls::Client::builder()
            .with_certificate(certificates::CERT_PEM)
            .unwrap()
            .build()
            .unwrap();

        let client = Client::builder()
            .with_io(handle.builder().build()?)?
            .with_tls(client)?
            .with_event(tracing_events())?
            .with_connection_id(ZeroLengthIdFormat)?
            .with_random(Random::with_seed(456))?
            .start()?;

        let addr = start_server(server)?;
        start_client(client, addr, Data::new(1000))?;

        Ok(())
    })
    .unwrap();
}
