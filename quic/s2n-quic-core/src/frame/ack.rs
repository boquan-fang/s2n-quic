use crate::{frame::Tag, varint::VarInt};
use core::{convert::TryInto, ops::RangeInclusive};
use s2n_codec::{
    decoder_parameterized_value, decoder_value, DecoderBuffer, DecoderError, Encoder, EncoderValue,
};

//=https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#rfc.section.19.3
//# 19.3.  ACK Frames
//#
//#    Receivers send ACK frames (types 0x02 and 0x03) to inform senders of
//#    packets they have received and processed.  The ACK frame contains one
//#    or more ACK Ranges.  ACK Ranges identify acknowledged packets.  If
//#    the frame type is 0x03, ACK frames also contain the sum of QUIC
//#    packets with associated ECN marks received on the connection up until
//#    this point.  QUIC implementations MUST properly handle both types
//#    and, if they have enabled ECN for packets they send, they SHOULD use
//#    the information in the ECN section to manage their congestion state.

macro_rules! ack_tag {
    () => {
        0x02u8..=0x03u8
    };
}
const ACK_TAG: u8 = 0x02;
const ACK_W_ECN_TAG: u8 = 0x03;

//#    QUIC acknowledgements are irrevocable.  Once acknowledged, a packet
//#    remains acknowledged, even if it does not appear in a future ACK
//#    frame.  This is unlike TCP SACKs ([RFC2018]).
//#
//#    It is expected that a sender will reuse the same packet number across
//#    different packet number spaces.  ACK frames only acknowledge the
//#    packet numbers that were transmitted by the sender in the same packet
//#    number space of the packet that the ACK was received in.
//#
//#    Version Negotiation and Retry packets cannot be acknowledged because
//#    they do not contain a packet number.  Rather than relying on ACK
//#    frames, these packets are implicitly acknowledged by the next Initial
//#    packet sent by the client.
//#
//#    An ACK frame is as follows:
//#
//#     0                   1                   2                   3
//#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                     Largest Acknowledged (i)                ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                          ACK Delay (i)                      ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                       ACK Range Count (i)                   ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                       First ACK Range (i)                   ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                          ACK Ranges (*)                     ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                          [ECN Counts]                       ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#
//#                         Figure 17: ACK Frame Format
//#
//#    ACK frames contain the following fields:
//#
//#    Largest Acknowledged:  A variable-length integer representing the
//#       largest packet number the peer is acknowledging; this is usually
//#       the largest packet number that the peer has received prior to
//#       generating the ACK frame.  Unlike the packet number in the QUIC
//#       long or short header, the value in an ACK frame is not truncated.
//#
//#    ACK Delay:  A variable-length integer representing the time delta in
//#       microseconds between when this ACK was sent and when the largest
//#       acknowledged packet, as indicated in the Largest Acknowledged
//#       field, was received by this peer.  The value of the ACK Delay
//#       field is scaled by multiplying the encoded value by 2 to the power
//#       of the value of the "ack_delay_exponent" transport parameter set
//#       by the sender of the ACK frame (see Section 18.1).  Scaling in
//#       this fashion allows for a larger range of values with a shorter
//#       encoding at the cost of lower resolution.  Because the receiver
//#       doesn't use the ACK Delay for Initial and Handshake packets, a
//#       sender SHOULD send a value of 0.
//#
//#    ACK Range Count:  A variable-length integer specifying the number of
//#       Gap and ACK Range fields in the frame.
//#
//#    First ACK Range:  A variable-length integer indicating the number of
//#       contiguous packets preceding the Largest Acknowledged that are
//#       being acknowledged.  The First ACK Range is encoded as an ACK
//#       Range (see Section 19.3.1) starting from the Largest Acknowledged.
//#       That is, the smallest packet acknowledged in the range is
//#       determined by subtracting the First ACK Range value from the
//#       Largest Acknowledged.
//#
//#    ACK Ranges:  Contains additional ranges of packets which are
//#       alternately not acknowledged (Gap) and acknowledged (ACK Range);
//#       see Section 19.3.1.
//#
//#    ECN Counts:  The three ECN Counts; see Section 19.3.2.

#[derive(Clone, PartialEq, Eq)]
pub struct Ack<AckRanges> {
    /// A variable-length integer representing the time delta in microseconds
    /// between when this ACK was sent and when the largest acknowledged
    /// packet, as indicated in the Largest Acknowledged field, was
    /// received by this peer
    pub ack_delay: VarInt,

    /// Contains additional ranges of packets which are alternately not
    /// acknowledged (Gap) and acknowledged (ACK Range)
    pub ack_ranges: AckRanges,

    /// ECN Counts
    pub ecn_counts: Option<ECNCounts>,
}

impl<AckRanges> Ack<AckRanges> {
    pub fn tag(&self) -> u8 {
        if self.ecn_counts.is_some() {
            ACK_W_ECN_TAG
        } else {
            ACK_TAG
        }
    }
}

impl<A: AckRanges> Ack<A> {
    pub fn ack_ranges(&self) -> A::Iter {
        self.ack_ranges.ack_ranges()
    }
}

impl<A: core::fmt::Debug> core::fmt::Debug for Ack<A> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_struct("Ack")
            .field("ack_delay", &self.ack_delay)
            .field("ack_ranges", &self.ack_ranges)
            .field("ecn_counts", &self.ecn_counts)
            .finish()
    }
}

decoder_parameterized_value!(
    impl<'a> Ack<AckRangesDecoder<'a>> {
        fn decode(tag: Tag, buffer: Buffer) -> Result<Self> {
            let (largest_acknowledged, buffer) = buffer.decode()?;
            let (ack_delay, buffer) = buffer.decode()?;
            let (ack_ranges, buffer) = buffer.decode_parameterized(largest_acknowledged)?;

            let (ecn_counts, buffer) = if tag == ACK_W_ECN_TAG {
                let (ecn_counts, buffer) = buffer.decode()?;
                (Some(ecn_counts), buffer)
            } else {
                (None, buffer)
            };

            let frame = Ack {
                ack_delay,
                ack_ranges,
                ecn_counts,
            };

            Ok((frame, buffer))
        }
    }
);

impl<A: AckRanges> EncoderValue for Ack<A> {
    fn encode<E: Encoder>(&self, buffer: &mut E) {
        buffer.encode(&self.tag());

        let mut iter = self.ack_ranges.ack_ranges();

        let first_ack_range = iter.next().expect("at least one ack range is required");
        let (mut smallest, largest_acknowledged) = first_ack_range.into_inner();
        let first_ack_range = largest_acknowledged - smallest;

        let ack_range_count: VarInt = iter
            .len()
            .try_into()
            .expect("ack range count cannot exceed VarInt::MAX");

        buffer.encode(&largest_acknowledged);
        buffer.encode(&self.ack_delay);
        buffer.encode(&ack_range_count);
        buffer.encode(&first_ack_range);

        for range in iter {
            smallest = encode_ack_range(range, smallest, buffer);
        }

        if let Some(ecn_counts) = self.ecn_counts.as_ref() {
            buffer.encode(ecn_counts);
        }
    }
}

//=https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#rfc.section.19.3.1
//# 19.3.1.  ACK Ranges
//#
//#    The ACK Ranges field consists of alternating Gap and ACK Range values
//#    in descending packet number order.  The number of Gap and ACK Range
//#    values is determined by the ACK Range Count field; one of each value
//#    is present for each value in the ACK Range Count field.

pub trait AckRanges {
    type Iter: Iterator<Item = RangeInclusive<VarInt>> + ExactSizeIterator;

    fn ack_ranges(&self) -> Self::Iter;
}

#[derive(Clone, Copy)]
pub struct AckRangesDecoder<'a> {
    largest_acknowledged: VarInt,
    ack_range_count: VarInt,
    range_buffer: DecoderBuffer<'a>,
}

impl<'a> AckRanges for AckRangesDecoder<'a> {
    type Iter = AckRangesIter<'a>;

    fn ack_ranges(&self) -> Self::Iter {
        AckRangesIter {
            largest_acknowledged: self.largest_acknowledged,
            ack_range_count: self.ack_range_count,
            range_buffer: self.range_buffer,
        }
    }
}

impl<'a> PartialEq for AckRangesDecoder<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.ack_ranges().eq(other.ack_ranges())
    }
}

impl<'a> core::fmt::Debug for AckRangesDecoder<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.ack_ranges(), f)
    }
}

//#    ACK Ranges are structured as follows:
//#
//#     0                   1                   2                   3
//#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                           [Gap (i)]                        ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                          [ACK Range (i)]                    ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                           [Gap (i)]                        ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                          [ACK Range (i)]                    ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#                                   ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                           [Gap (i)]                        ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                          [ACK Range (i)]                    ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#
//#                            Figure 18: ACK Ranges
//#
//#    The fields that form the ACK Ranges are:
//#
//#    Gap (repeated):  A variable-length integer indicating the number of
//#       contiguous unacknowledged packets preceding the packet number one
//#       lower than the smallest in the preceding ACK Range.
//#
//#    ACK Range (repeated):  A variable-length integer indicating the
//#       number of contiguous acknowledged packets preceding the largest
//#       packet number, as determined by the preceding Gap.
//#
//#    Gap and ACK Range value use a relative integer encoding for
//#    efficiency.  Though each encoded value is positive, the values are
//#    subtracted, so that each ACK Range describes progressively lower-
//#    numbered packets.
//#
//#    Each ACK Range acknowledges a contiguous range of packets by
//#    indicating the number of acknowledged packets that precede the
//#    largest packet number in that range.  A value of zero indicates that
//#    only the largest packet number is acknowledged.  Larger ACK Range
//#    values indicate a larger range, with corresponding lower values for
//#    the smallest packet number in the range.  Thus, given a largest
//#    packet number for the range, the smallest value is determined by the
//#    formula:
//#
//#       smallest = largest - ack_range

decoder_parameterized_value!(
    impl<'a> AckRangesDecoder<'a> {
        fn decode(largest_acknowledged: VarInt, buffer: Buffer) -> Result<AckRangesDecoder> {
            let (mut ack_range_count, buffer) = buffer.decode::<VarInt>()?;

            // add one to the total, which includes the first ack range
            ack_range_count = ack_range_count
                .checked_add(VarInt::from_u8(1))
                .ok_or(ACK_RANGE_DECODING_ERROR)?;

            let mut iter = AckRangesIter {
                ack_range_count,
                range_buffer: buffer.peek(),
                largest_acknowledged,
            };

            // make sure we can decode all of the range/gap pairs
            for _ in 0..*ack_range_count {
                iter.next().ok_or(ACK_RANGE_DECODING_ERROR)?;
            }

            let peek_len = iter.range_buffer.len();
            let buffer_len = buffer.len();
            debug_assert!(
                buffer_len >= peek_len,
                "peeked buffer should never consume more than actual buffer"
            );
            let (range_buffer, remaining) = buffer.decode_slice(buffer_len - peek_len)?;

            #[allow(clippy::identity_conversion)]
            let range_buffer = range_buffer.into();

            let ack_ranges = AckRangesDecoder {
                ack_range_count,
                range_buffer,
                largest_acknowledged,
            };

            Ok((ack_ranges, remaining))
        }
    }
);

//#    An ACK Range acknowledges all packets between the smallest packet
//#    number and the largest, inclusive.
//#
//#    The largest value for an ACK Range is determined by cumulatively
//#    subtracting the size of all preceding ACK Ranges and Gaps.
//#
//#    Each Gap indicates a range of packets that are not being
//#    acknowledged.  The number of packets in the gap is one higher than
//#    the encoded value of the Gap field.
//#
//#    The value of the Gap field establishes the largest packet number
//#    value for the subsequent ACK Range using the following formula:
//#
//#       largest = previous_smallest - gap - 2

fn encode_ack_range<E: Encoder>(
    range: RangeInclusive<VarInt>,
    smallest: VarInt,
    buffer: &mut E,
) -> VarInt {
    let (start, end) = range.into_inner();
    let gap = smallest - end - 2;
    let ack_range = end - start;

    buffer.encode(&gap);
    buffer.encode(&ack_range);

    start
}

#[derive(Clone, Copy)]
pub struct AckRangesIter<'a> {
    largest_acknowledged: VarInt,
    ack_range_count: VarInt,
    range_buffer: DecoderBuffer<'a>,
}

impl<'a> Iterator for AckRangesIter<'a> {
    type Item = RangeInclusive<VarInt>;

    fn next(&mut self) -> Option<Self::Item> {
        self.ack_range_count = self.ack_range_count.checked_sub(VarInt::from_u8(1))?;

        let largest_acknowledged = self.largest_acknowledged;
        let (ack_range, buffer) = self.range_buffer.decode::<VarInt>().ok()?;

        let start = largest_acknowledged.checked_sub(ack_range)?;
        let end = largest_acknowledged;

        // If we're not on the last range, try to decode the next gap
        self.range_buffer = if self.ack_range_count != VarInt::from_u8(0) {
            let (gap, buffer) = buffer.decode::<VarInt>().ok()?;
            self.largest_acknowledged = largest_acknowledged
                .checked_sub(ack_range)?
                .checked_sub(gap)?
                .checked_sub(VarInt::from_u8(2))?;
            buffer
        } else {
            buffer
        };

        Some(start..=end)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let ack_range_count = *self.ack_range_count as usize;
        (ack_range_count, Some(ack_range_count))
    }
}

impl<'a> ExactSizeIterator for AckRangesIter<'a> {}

impl<'a> core::fmt::Debug for AckRangesIter<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.debug_list().entries(*self).finish()
    }
}

//#    If any computed packet number is negative, an endpoint MUST generate
//#    a connection error of type FRAME_ENCODING_ERROR indicating an error
//#    in an ACK frame.

const ACK_RANGE_DECODING_ERROR: DecoderError =
    DecoderError::InvariantViolation("invalid ACK ranges");

//=https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#rfc.section.19.3.2
//# 19.3.2.  ECN Counts
//#
//#    The ACK frame uses the least significant bit (that is, type 0x03) to
//#    indicate ECN feedback and report receipt of QUIC packets with
//#    associated ECN codepoints of ECT(0), ECT(1), or CE in the packet's IP
//#    header.  ECN Counts are only present when the ACK frame type is 0x03.
//#
//#    ECN Counts are only parsed when the ACK frame type is 0x03.  There
//#    are 3 ECN counts, as follows:
//#
//#     0                   1                   2                   3
//#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                        ECT(0) Count (i)                     ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                        ECT(1) Count (i)                     ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                        ECN-CE Count (i)                     ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#
//#    The three ECN Counts are:
//#
//#    ECT(0) Count:  A variable-length integer representing the total
//#       number of packets received with the ECT(0) codepoint.
//#
//#    ECT(1) Count:  A variable-length integer representing the total
//#       number of packets received with the ECT(1) codepoint.
//#
//#    CE Count:  A variable-length integer representing the total number of
//#       packets received with the CE codepoint.
//#
//#    ECN counts are maintained separately for each packet number space.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ECNCounts {
    /// A variable-length integer representing the total number of packets
    /// received with the ECT(0) codepoint.
    pub ect_0_count: VarInt,

    /// A variable-length integer representing the total number of packets
    /// received with the ECT(1) codepoint.
    pub ect_1_count: VarInt,

    /// A variable-length integer representing the total number of packets
    /// received with the CE codepoint.
    pub ce_count: VarInt,
}

decoder_value!(
    impl<'a> ECNCounts {
        fn decode(buffer: Buffer) -> Result<Self> {
            let (ect_0_count, buffer) = buffer.decode()?;
            let (ect_1_count, buffer) = buffer.decode()?;
            let (ce_count, buffer) = buffer.decode()?;

            let ecn_counts = Self {
                ect_0_count,
                ect_1_count,
                ce_count,
            };

            Ok((ecn_counts, buffer))
        }
    }
);

impl EncoderValue for ECNCounts {
    fn encode<E: Encoder>(&self, buffer: &mut E) {
        buffer.encode(&self.ect_0_count);
        buffer.encode(&self.ect_1_count);
        buffer.encode(&self.ce_count);
    }
}