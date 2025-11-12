// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::tag::Common;
use core::fmt;
use zerocopy::{FromBytes, Unaligned};

pub mod decoder;
pub mod encoder;

#[derive(Clone, Copy, PartialEq, Eq, FromBytes, Unaligned)]
#[repr(C)]
pub struct Tag(Common);

impl_tag_codec!(Tag);

impl Default for Tag {
    #[inline]
    fn default() -> Self {
        Self(Common(0b0111_0000))
    }
}

impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("mtu_probing_complete::Tag")
            .field("padding", &0b0000)
            .finish()
    }
}

impl Tag {
    pub const PADDING: u8 = 0b0000;

    pub const MIN: u8 = 0b0111_0000;
    pub const MAX: u8 = 0b0111_1111;

    #[inline]
    pub fn set_padding(&mut self) {
        self.0.set(Self::PADDING, true);
    }

    #[inline]
    fn validate(&self) -> Result<(), s2n_codec::DecoderError> {
        s2n_codec::decoder_invariant!(
            (self.0).0 == 0b0111_0000,
            "invalid mtu_probing_complete bit pattern"
        );
        Ok(())
    }
}
