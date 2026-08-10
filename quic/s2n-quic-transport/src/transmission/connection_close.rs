// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::transmission::{self, WriteContext};
use core::ops::RangeInclusive;
use s2n_codec::EncoderValue;
use s2n_quic_core::{ack, frame, frame::Ack};

pub struct Payload<'a> {
    pub connection_close: &'a frame::ConnectionClose<'a>,

    /// An optional ACK frame to bundle into the same packet as the `CONNECTION_CLOSE`.
    ///
    /// When present, the ACK is written *before* the `CONNECTION_CLOSE` frame. A peer stops
    /// processing frames as soon as it encounters a `CONNECTION_CLOSE`, so any frame ordered
    /// after it would be ignored. Bundling the ACK here lets it inherit the close packet's
    /// reliable retransmission, ensuring an ACK the peer is waiting on survives packet loss even
    /// though a standalone ACK would not be retransmitted once we start closing.
    pub ack: Option<Ack<&'a ack::Ranges>>,
}

impl super::Payload for Payload<'_> {
    fn size_hint(&self, range: RangeInclusive<usize>) -> usize {
        let ack_size = self.ack.as_ref().map_or(0, |ack| ack.encoding_size());
        (*range.start()).max(self.connection_close.encoding_size() + ack_size)
    }

    fn on_transmit<W: WriteContext>(&mut self, context: &mut W) {
        // Write the ACK before the CONNECTION_CLOSE. The peer stops processing frames once it
        // sees a CONNECTION_CLOSE, so an ACK placed after it would never be processed.
        if let Some(ack) = self.ack.as_ref() {
            context.write_ack_frame(ack);
        }
        context.write_frame(self.connection_close);
    }
}

impl transmission::interest::Provider for Payload<'_> {
    #[inline]
    fn transmission_interest<Q: transmission::interest::Query>(
        &self,
        query: &mut Q,
    ) -> transmission::interest::Result {
        //= https://www.rfc-editor.org/rfc/rfc9002#section-3
        //# Packets containing frames besides ACK or CONNECTION_CLOSE frames
        //# count toward congestion control limits and are considered to be in
        //# flight.

        // this packet only contains an ACK and/or a CONNECTION_CLOSE so bypass the CC
        query.on_forced()
    }
}
