//! Types and utilities around the QUIC Stream identifier

use crate::{endpoint::EndpointType, stream::StreamType, varint::VarInt};

//=https://tools.ietf.org/html/draft-ietf-quic-transport-24#section-2.1
//# 2.1.  Stream Types and Identifiers
//#
//#    Streams can be unidirectional or bidirectional.  Unidirectional
//#    streams carry data in one direction: from the initiator of the stream
//#    to its peer.  Bidirectional streams allow for data to be sent in both
//#    directions.
//#
//#    Streams are identified within a connection by a numeric value,
//#    referred to as the stream ID.  A stream ID is a 62-bit integer (0 to
//#    2^62-1) that is unique for all streams on a connection.  Stream IDs
//#    are encoded as variable-length integers (see Section 16).  A QUIC
//#    endpoint MUST NOT reuse a stream ID within a connection.
//#
//#    The least significant bit (0x1) of the stream ID identifies the
//#    initiator of the stream.  Client-initiated streams have even-numbered
//#    stream IDs (with the bit set to 0), and server-initiated streams have
//#    odd-numbered stream IDs (with the bit set to 1).
//#
//#    The second least significant bit (0x2) of the stream ID distinguishes
//#    between bidirectional streams (with the bit set to 0) and
//#    unidirectional streams (with the bit set to 1).
//#
//#    The least significant two bits from a stream ID therefore identify a
//#    stream as one of four types, as summarized in Table 1.
//#
//#                 +------+----------------------------------+
//#                 | Bits | Stream Type                      |
//#                 +------+----------------------------------+
//#                 | 0x0  | Client-Initiated, Bidirectional  |
//#                 |      |                                  |
//#                 | 0x1  | Server-Initiated, Bidirectional  |
//#                 |      |                                  |
//#                 | 0x2  | Client-Initiated, Unidirectional |
//#                 |      |                                  |
//#                 | 0x3  | Server-Initiated, Unidirectional |
//#                 +------+----------------------------------+
//#
//#                          Table 1: Stream ID Types
//#
//#    Within each type, streams are created with numerically increasing
//#    stream IDs.  A stream ID that is used out of order results in all
//#    streams of that type with lower-numbered stream IDs also being
//#    opened.
//#
//#    The first bidirectional stream opened by the client has a stream ID
//#    of 0.

/// The ID of a stream.
///
/// A stream ID is a 62-bit integer (0 to 2^62-1) that is unique for all streams
/// on a connection.
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Copy, Clone, Hash)]
pub struct StreamId(VarInt);

// Stream IDs can be converted into `VarInt` and `u64`

impl Into<VarInt> for StreamId {
    fn into(self) -> VarInt {
        self.0
    }
}

impl Into<u64> for StreamId {
    fn into(self) -> u64 {
        self.0.into()
    }
}

impl StreamId {
    /// Creates a Stream ID from a [`VarInt`].
    ///
    /// This is always a safe conversion, since Stream IDs and [`VarInt`]s
    /// share the same range.
    #[inline]
    pub const fn from_varint(id: VarInt) -> StreamId {
        StreamId(id)
    }

    /// Returns the initial Stream ID for a given stream type.
    ///
    /// E.g. the initial Stream ID for a server initiated unidirectional Stream
    /// is Stream ID `3`.
    ///
    /// Example:
    ///
    /// ```
    /// # use s2n_quic_core::{endpoint::EndpointType, stream::{StreamId, StreamType}};
    /// let stream_id = StreamId::initial(EndpointType::Server, StreamType::Unidirectional);
    /// // Initial server initiated unidirectional Stream ID is 3
    /// assert_eq!(3u64, stream_id.into());
    /// ```
    #[inline]
    pub fn initial(initator: EndpointType, stream_type: StreamType) -> StreamId {
        match (
            stream_type == StreamType::Bidirectional,
            initator == EndpointType::Client,
        ) {
            (true, true) => StreamId(VarInt::from_u32(0)),
            (true, false) => StreamId(VarInt::from_u32(1)),
            (false, true) => StreamId(VarInt::from_u32(2)),
            (false, false) => StreamId(VarInt::from_u32(3)),
        }
    }

    /// Returns the n-th `StreamId` for a certain type of `Stream`.
    ///
    /// The 0th `StreamId` thereby represents the `StreamId` which is returned
    /// by the [`initial`] method. All further `StreamId`s of a certain type
    /// will be spaced apart by 4.
    ///
    /// nth() will return `None` if the resulting `StreamId` would not be valid.
    #[inline]
    pub fn nth(initiator: EndpointType, stream_type: StreamType, n: usize) -> Option<StreamId> {
        let initial = Self::initial(initiator, stream_type);
        // We calculate as much as possible with u64, to reduce the number of
        // overflow checks for the maximum Stream ID to the last operation
        let id = VarInt::new((n as u64).checked_mul(4)?.checked_add(initial.into())?).ok()?;
        Some(StreamId(id))
    }

    /// Returns the next [`StreamId`] which is of the same type the one referred
    /// to. E.g. if the method is called on a Stream ID for an unidirectional
    /// client initiated stream, the Stream ID of the next unidirectional client
    /// initiated stream will be returned.
    ///
    /// Returns `None` if the next Stream ID would not be valid, due to being out
    /// of bounds.
    ///
    /// Example:
    ///
    /// ```
    /// # use s2n_quic_core::{endpoint::EndpointType, stream::{StreamId, StreamType}};
    /// let stream_id = StreamId::initial(EndpointType::Client, StreamType::Unidirectional);
    /// // Initial client initiated unidirectional Stream ID is 2
    /// assert_eq!(2u64, stream_id.into());
    /// // Get the next client initiated Stream ID
    /// let next_stream_id = stream_id.next_of_type();
    /// assert_eq!(6u64, next_stream_id.expect("Next Stream ID is valid").into());
    /// ```
    #[inline]
    pub fn next_of_type(self) -> Option<StreamId> {
        // Stream IDs increase in steps of 4, since the 2 least significant bytes
        // are used to indicate the stream type
        self.0
            .checked_add(VarInt::from_u32(4))
            .map(StreamId::from_varint)
    }

    /// Returns whether the client or server initated the Stream
    #[inline]
    pub fn initiator(self) -> EndpointType {
        //# The least significant bit (0x1) of the stream ID identifies the
        //# initiator of the stream.  Client-initiated streams have even-numbered
        //# stream IDs (with the bit set to 0)
        if Into::<u64>::into(self.0) & 0x01u64 == 0 {
            EndpointType::Client
        } else {
            EndpointType::Server
        }
    }

    /// Returns whether the Stream is unidirectional or bidirectional.
    #[inline]
    pub fn stream_type(self) -> StreamType {
        //# The second least significant bit (0x2) of the stream ID distinguishes
        //# between bidirectional streams (with the bit set to 0) and
        //# unidirectional streams (with the bit set to 1).
        if Into::<u64>::into(self.0) & 0x02 == 0 {
            StreamType::Bidirectional
        } else {
            StreamType::Unidirectional
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::varint::MAX_VARINT_VALUE;

    #[test]
    fn initial_stream_ids() {
        for stream_type in &[StreamType::Bidirectional, StreamType::Unidirectional] {
            for initiator in &[EndpointType::Client, EndpointType::Server] {
                let id = StreamId::initial(*initiator, *stream_type);
                assert_eq!(*stream_type, id.stream_type());
                assert_eq!(*initiator, id.initiator());
            }
        }
    }

    #[test]
    fn stream_id_overflow() {
        // Check that the highest possible Stream ID works
        let max_stream_id_varint = VarInt::new((1 << 62) - 1).unwrap();
        let _max_stream_id = StreamId::from_varint(max_stream_id_varint);

        let max_increaseable_stream_id_varint = max_stream_id_varint - 4;
        let max_inreasable_stream_id = StreamId::from_varint(max_increaseable_stream_id_varint);
        assert!(max_inreasable_stream_id.next_of_type().is_some());

        // Check all the variants where the base ID is still valid but the
        // increment is no longer.
        for increment in 1..5 {
            let id_varint = max_increaseable_stream_id_varint + increment;
            let stream_id = StreamId::from_varint(id_varint);
            assert!(stream_id.next_of_type().is_none());
        }
    }

    #[test]
    fn nth_stream_id() {
        for stream_type in &[StreamType::Bidirectional, StreamType::Unidirectional] {
            for initiator in &[EndpointType::Client, EndpointType::Server] {
                // The first StreamId is the initial one
                let first = StreamId::nth(*initiator, *stream_type, 0).unwrap();
                assert_eq!(StreamId::initial(*initiator, *stream_type), first);

                for n in 1..10 {
                    let nth = StreamId::nth(*initiator, *stream_type, n).unwrap();
                    assert_eq!(VarInt::from_u32(n as u32 * 4), nth.0 - first.0);
                }
            }
        }
    }

    #[test]
    fn invalid_nth_stream_id() {
        for stream_type in &[StreamType::Bidirectional, StreamType::Unidirectional] {
            for initiator in &[EndpointType::Client, EndpointType::Server] {
                assert_eq!(
                    None,
                    StreamId::nth(
                        *initiator,
                        *stream_type,
                        Into::<u64>::into(MAX_VARINT_VALUE / 2) as usize
                    )
                );
            }
        }
    }
}