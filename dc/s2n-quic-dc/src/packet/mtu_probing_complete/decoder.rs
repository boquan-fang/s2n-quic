use crate::{
    credentials::Credentials,
    packet::{mtu_probing_complete::Tag, WireVersion},
};
use s2n_codec::{decoder_invariant, DecoderBufferMut, DecoderBufferMutResult as R, DecoderError};
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

pub struct Packet<'a> {
    tag: Tag,
    wire_version: WireVersion,
    credentials: Credentials,
    source_control_port: u16,
    packet_number: PacketNumber,
    header: &'a mut [u8],
    mtu: u16,
    auth_tag: &'a mut [u8],
}

impl std::fmt::Debug for Packet<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Packet")
            .field("tag", &self.tag)
            .field("wire_version", &self.wire_version)
            .field("credentials", &self.credentials)
            .field("source_control_port", &self.source_control_port)
            .field("packet_number", &self.packet_number)
            .field("header", &self.header)
            .field("mtu", &self.mtu)
            .field("auth_tag", &self.auth_tag)
            .finish()
    }
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
    pub fn source_control_port(&self) -> u16 {
        self.source_control_port
    }

    #[inline]
    pub fn crypto_nonce(&self) -> u64 {
        self.packet_number.as_u64()
    }

    #[inline]
    pub fn packet_number(&self) -> PacketNumber {
        self.packet_number
    }

    #[inline]
    pub fn header(&self) -> &[u8] {
        self.header
    }

    #[inline]
    pub fn mtu(&self) -> u16 {
        self.mtu
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
            source_control_port,
            packet_number,
            header,
            mtu,
            auth_tag,
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

            let (source_control_port, buffer) = buffer.decode()?;
            
            let (packet_number, buffer) = buffer.decode()?;
        }
    }
}
