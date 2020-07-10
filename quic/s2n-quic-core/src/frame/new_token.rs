use crate::{frame::Tag, varint::VarInt};
use s2n_codec::{decoder_parameterized_value, Encoder, EncoderValue};

//=https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#rfc.section.19.7
//# 19.7.  NEW_TOKEN Frame
//#
//#    A server sends a NEW_TOKEN frame (type=0x07) to provide the client
//#    with a token to send in the header of an Initial packet for a future
//#    connection.

macro_rules! new_token_tag {
    () => {
        0x07u8
    };
}

//#    The NEW_TOKEN frame is as follows:
//#
//#     0                   1                   2                   3
//#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                        Token Length (i)                     ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#    |                            Token (*)                        ...
//#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//#
//#    NEW_TOKEN frames contain the following fields:
//#
//#    Token Length:  A variable-length integer specifying the length of the
//#       token in bytes.
//#
//#    Token:  An opaque blob that the client may use with a future Initial
//#       packet.

#[derive(Debug, PartialEq, Eq)]
pub struct NewToken<'a> {
    /// An opaque blob that the client may use with a future Initial packet.
    pub token: &'a [u8],
}

impl<'a> NewToken<'a> {
    pub const fn tag(&self) -> u8 {
        new_token_tag!()
    }
}

decoder_parameterized_value!(
    impl<'a> NewToken<'a> {
        fn decode(_tag: Tag, buffer: Buffer) -> Result<Self> {
            let (token, buffer) = buffer.decode_slice_with_len_prefix::<VarInt>()?;
            let token = token.into_less_safe_slice();

            let frame = NewToken { token };

            Ok((frame, buffer))
        }
    }
);

impl<'a> EncoderValue for NewToken<'a> {
    fn encode<E: Encoder>(&self, buffer: &mut E) {
        buffer.encode(&self.tag());
        buffer.encode_with_len_prefix::<VarInt, _>(&self.token);
    }
}