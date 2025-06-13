// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::provider::tls::default::{self as tls};

#[test]
fn zero_length_cid_client_connection_migration_test() {
    let model = Model::default();

    // TODO:: Create event subscribers

    test(model, |handle| {
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

        let addr = start_server(server)?;

        Ok(())
    })
    .unwrap();
}
