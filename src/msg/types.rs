//! Module containing types that are used throughout the protocol
use super::codec::*;
use bytes::Bytes;
use num_enum::{FromPrimitive, IntoPrimitive};
use rsa::rand_core::{OsRng, RngCore};
use std::fmt::Debug;

/// Different types of SSLMessages
#[derive(Debug, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum MessageType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    #[num_enum(default)]
    Unknown,
}

impl EnumCodec for MessageType {}

// Alert level type. Warning can be dimissed but Fatal must result
// in connection termination. In this use case we will terminate
// the connection if any sort of Alert is obtained
#[derive(Debug, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum AlertLevel {
    Warning = 1,
    Fatal = 2,
    #[num_enum(default)]
    Unknown,
}

impl EnumCodec for AlertLevel {}

// Extra details pertaining to the type of Alert recieved extends
// upon AlertLevel providing more context
#[derive(Debug, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum AlertDescription {
    CloseNotify = 0x0,
    UnexpectedMessage = 0xA,
    BadRecordMac = 0x14,
    DecompressionFailure = 0x1E,
    HandshakeFailure = 0x28,
    NoCertificate = 0x29,
    BadCertificate = 0x2A,
    UnsupportedCertificate = 0x2B,
    CertificateRevoked = 0x2C,
    CertificateExpired = 0x2D,
    CertificateUnknown = 0x2E,
    IllegalParameter = 0x2F,
    #[num_enum(default)]
    Unknown,
}

impl EnumCodec for AlertDescription {}

// SSL protocol versions enum. This only contains SSLv3 because
// thats the only protocol we implement
#[derive(Debug, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum ProtocolVersion {
    SSLv3 = 0x0300,
    #[num_enum(default)]
    Unknown,
}

impl EnumCodec for ProtocolVersion {}

impl ProtocolVersion {
    /// Hard coded only supporting SSLv3 protocol version
    pub fn is_valid(&self) -> bool {
        matches!(self, ProtocolVersion::SSLv3)
    }
}

// Cipher suites known to this application
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, FromPrimitive, IntoPrimitive)]
#[repr(u16)]
pub enum CipherSuite {
    TLS_RSA_WITH_RC4_128_MD5 = 0x0004,
    TLS_RSA_WITH_RC4_128_SHA = 0x0005,
    #[num_enum(default)]
    Unknown,
}

impl EnumCodec for CipherSuite {}

// Type of handshake message
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    Certificate = 11,
    ServerHelloDone = 14,
    ClientKeyExchange = 16,
    Finished = 20,
    #[num_enum(default)]
    Unknown,
}

impl EnumCodec for HandshakeType {}

/// DER-encoded X.509 certificate bytes representing
/// a certificate
#[derive(Clone)]
pub struct Certificate(pub(crate) Bytes);

impl Certificate {
    /// Creates a new certificate from static bytes
    #[inline]
    pub fn from_static(bytes: &'static [u8]) -> Self {
        Self(Bytes::from_static(bytes))
    }
}

impl From<Vec<u8>> for Certificate {
    fn from(value: Vec<u8>) -> Self {
        Self(Bytes::from(value))
    }
}

impl Codec for Certificate {
    fn encode(self, output: &mut Vec<u8>) {
        let bytes: &[u8] = &self.0;
        u24::from(bytes.len()).encode(output);
        output.extend_from_slice(bytes)
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let length: usize = u24::decode(input)?.into();

        input
            .take(length)
            // Copy the inner bytes from the slice
            .map(Bytes::copy_from_slice)
            .map(Self)
    }
}

/// 32 random bytes generated for SSL encryption
#[derive(Clone)]
pub struct SSLRandom(pub [u8; 32]);

impl SSLRandom {
    /// Creates a new SSL random using [OsRng]
    pub fn random() -> Self {
        let mut this = Self(Default::default());
        OsRng.fill_bytes(&mut this.0);
        this
    }
}

impl Codec for SSLRandom {
    fn encode(self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        input.take_fixed::<32>().map(Self)
    }
}
