// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    credentials::Credentials,
    packet::{control::Tag, stream, WireVersion},
};
use s2n_codec::{
    decoder_invariant, CheckedRange, DecoderBufferMut, DecoderBufferMutResult as R, DecoderError,
};
use s2n_quic_core::{assume, varint::VarInt};

type PacketNumber = VarInt;

pub trait Validator {
    fn validate_tag(&mut self, tag: Tag) -> Result<(), DecoderError>;
}

impl Validator for () {
    #[inline]
    fn validate_tag(&mut self, _tag: Tag) -> Result<(), DecoderError> {
        Ok(())
    }
}

impl Validator for Tag {
    #[inline]
    fn validate_tag(&mut self, actual: Tag) -> Result<(), DecoderError> {
        decoder_invariant!(*self == actual, "unexpected packet type");
        Ok(())
    }
}

impl<A, B> Validator for (A, B)
where
    A: Validator,
    B: Validator,
{
    #[inline]
    fn validate_tag(&mut self, tag: Tag) -> Result<(), DecoderError> {
        self.0.validate_tag(tag)?;
        self.1.validate_tag(tag)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Packet<'a> {
    tag: Tag,
    wire_version: WireVersion,
    credentials: Credentials,
    source_queue_id: Option<VarInt>,
    stream_id: Option<stream::Id>,
    packet_number: PacketNumber,
    header: &'a mut [u8],
    application_header: CheckedRange,
    control_data: CheckedRange,
    auth_tag: &'a mut [u8],
}

impl Packet<'_> {
    #[inline]
    pub fn tag(&self) -> Tag {
        self.tag
    }

    #[inline]
    pub fn wire_version(&self) -> WireVersion {
        self.wire_version
    }

    #[inline]
    pub fn credentials(&self) -> &Credentials {
        &self.credentials
    }

    #[inline]
    pub fn source_queue_id(&self) -> Option<VarInt> {
        self.source_queue_id
    }

    #[inline]
    pub fn stream_id(&self) -> Option<&stream::Id> {
        self.stream_id.as_ref()
    }

    #[inline]
    pub fn packet_number(&self) -> PacketNumber {
        self.packet_number
    }

    #[inline]
    pub fn application_header(&self) -> &[u8] {
        self.application_header.get(self.header)
    }

    #[inline]
    pub fn control_data(&self) -> &[u8] {
        self.control_data.get(self.header)
    }

    #[inline]
    pub fn control_data_mut(&mut self) -> &mut [u8] {
        self.control_data.get_mut(self.header)
    }

    #[inline]
    pub fn header(&self) -> &[u8] {
        self.header
    }

    #[inline]
    pub fn auth_tag(&self) -> &[u8] {
        self.auth_tag
    }

    #[inline(always)]
    pub fn decode<V: Validator>(
        buffer: DecoderBufferMut,
        mut validator: V,
        crypto_tag_len: usize,
    ) -> R<Packet> {
        let (
            tag,
            wire_version,
            credentials,
            source_queue_id,
            stream_id,
            packet_number,
            header_len,
            total_header_len,
            application_header_len,
            control_data_len,
        ) = {
            let buffer = buffer.peek();

            unsafe {
                assume!(
                    crypto_tag_len >= 16,
                    "tag len needs to be at least 16 bytes"
                );
            }

            let start_len = buffer.len();

            let (tag, buffer) = buffer.decode()?;
            validator.validate_tag(tag)?;

            let (credentials, buffer) = buffer.decode()?;
            let (wire_version, buffer) = buffer.decode()?;

            let (stream_id, buffer) = if tag.is_stream() {
                let (stream_id, buffer) = buffer.decode()?;
                (Some(stream_id), buffer)
            } else {
                (None, buffer)
            };

            let (source_queue_id, buffer) = if tag.has_source_queue_id() {
                let (v, buffer) = buffer.decode()?;
                (Some(v), buffer)
            } else {
                (None, buffer)
            };

            let (packet_number, buffer) = buffer.decode::<VarInt>()?;
            let (control_data_len, buffer) = buffer.decode::<VarInt>()?;

            let (application_header_len, buffer) = if tag.has_application_header() {
                let (application_header_len, buffer) = buffer.decode::<VarInt>()?;
                ((*application_header_len) as usize, buffer)
            } else {
                (0, buffer)
            };

            let header_len = start_len - buffer.len();

            let buffer = buffer.skip(application_header_len)?;
            let buffer = buffer.skip(*control_data_len as _)?;

            let total_header_len = start_len - buffer.len();

            let buffer = buffer.skip(crypto_tag_len)?;

            let _ = buffer;

            (
                tag,
                wire_version,
                credentials,
                source_queue_id,
                stream_id,
                packet_number,
                header_len,
                total_header_len,
                application_header_len,
                control_data_len,
            )
        };

        unsafe {
            assume!(buffer.len() >= total_header_len);
        }
        let (header, buffer) = buffer.decode_slice(total_header_len)?;

        let (application_header, control_data) = {
            let buffer = header.peek();
            unsafe {
                assume!(buffer.len() >= header_len);
            }
            let buffer = buffer.skip(header_len)?;
            unsafe {
                assume!(buffer.len() >= application_header_len);
            }
            let (application_header, buffer) =
                buffer.skip_into_range(application_header_len, &header)?;
            unsafe {
                assume!(buffer.len() >= *control_data_len as usize);
            }
            let (control_data, _) = buffer.skip_into_range(*control_data_len as usize, &header)?;

            (application_header, control_data)
        };
        let header = header.into_less_safe_slice();

        let (auth_tag, buffer) = buffer.decode_slice(crypto_tag_len)?;
        let auth_tag = auth_tag.into_less_safe_slice();

        let packet = Packet {
            tag,
            wire_version,
            credentials,
            source_queue_id,
            stream_id,
            packet_number,
            header,
            application_header,
            control_data,
            auth_tag,
        };

        Ok((packet, buffer))
    }
}
