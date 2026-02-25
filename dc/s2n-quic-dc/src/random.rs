// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub use s2n_quic_core::random::*;

use s2n_quic::provider::random::{AwsLc, Random as Inner};

pub struct Random(Inner<AwsLc>);

impl Default for Random {
    #[inline]
    fn default() -> Self {
        Self(Inner::new(AwsLc, AwsLc))
    }
}

impl Generator for Random {
    #[inline]
    fn public_random_fill(&mut self, dest: &mut [u8]) {
        self.0.public_random_fill(dest);
    }

    #[inline]
    fn private_random_fill(&mut self, dest: &mut [u8]) {
        self.0.private_random_fill(dest);
    }
}
