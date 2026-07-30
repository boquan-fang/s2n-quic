// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    ack::AckManager,
    transmission::{self, WriteContext},
};
use core::ops::RangeInclusive;
use s2n_codec::EncoderValue;
use s2n_quic_core::frame;

pub struct Payload<'a> {
    pub connection_close: &'a frame::ConnectionClose<'a>,
}

impl super::Payload for Payload<'_> {
    fn size_hint(&self, range: RangeInclusive<usize>) -> usize {
        (*range.start()).max(self.connection_close.encoding_size())
    }

    fn on_transmit<W: WriteContext>(&mut self, context: &mut W) {
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

        // this packet only contains a CONNECTION_CLOSE so bypass the CC
        query.on_forced()
    }
}

/// A closing payload that optionally bundles the pending ACK ahead of the `CONNECTION_CLOSE`
/// frame.
///
/// When `ack_manager` is `Some`, the ACK is written *before* the close so the peer processes it
/// first: frame processing short-circuits on `CONNECTION_CLOSE`, so any frame ordered after it
/// would be ignored. Bundling the ACK onto the close packet lets the acknowledgement inherit the
/// close's retransmission for the closing period, which is how the dc server receives the ACK of
/// its `DC_STATELESS_RESET_TOKENS` even when the client's standalone ACK is lost.
///
/// When `ack_manager` is `None` this behaves exactly like the plain [`Payload`] and writes only
/// the close frame. This is used to confine the bundled-ACK behavior to dc connections, leaving
/// every other connection's close packet unchanged.
pub struct PayloadWithAck<'a> {
    pub ack_manager: Option<&'a AckManager>,
    pub connection_close: &'a frame::ConnectionClose<'a>,
}

impl super::Payload for PayloadWithAck<'_> {
    fn size_hint(&self, range: RangeInclusive<usize>) -> usize {
        (*range.start()).max(self.connection_close.encoding_size())
    }

    fn on_transmit<W: WriteContext>(&mut self, context: &mut W) {
        // ACK first: the peer stops processing frames after CONNECTION_CLOSE.
        if let Some(ack_manager) = self.ack_manager {
            ack_manager.write_ack_frame_forced(context);
        }
        context.write_frame(self.connection_close);
    }
}

impl transmission::interest::Provider for PayloadWithAck<'_> {
    #[inline]
    fn transmission_interest<Q: transmission::interest::Query>(
        &self,
        query: &mut Q,
    ) -> transmission::interest::Result {
        //= https://www.rfc-editor.org/rfc/rfc9002#section-3
        //# Packets containing frames besides ACK or CONNECTION_CLOSE frames
        //# count toward congestion control limits and are considered to be in
        //# flight.

        // this packet only contains an ACK and a CONNECTION_CLOSE so bypass the CC
        query.on_forced()
    }
}
