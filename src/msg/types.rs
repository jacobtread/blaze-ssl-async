//! Module containing types that are used throughout the protocol
use super::codec::*;
use bytes::Bytes;
use rsa::rand_core::{OsRng, RngCore};
use std::fmt::{Debug, Display};

codec_enum! {
    // Enum describing the type of content stored in a SSLMessage
    (u8) enum MessageType {
        ChangeCipherSpec = 20,
        Alert = 21,
        Handshake = 22,
        ApplicationData = 23,
    }
}

codec_enum! {
    // Alert level type. Warning can be dimissed but Fatal must result
    // in connection termination. In this use case we will terminate
    // the connection if any sort of Alert is obtained
    (u8) enum AlertLevel {
        Warning = 1,
        Fatal = 2,
    }
}

impl Display for AlertLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

codec_enum! {
    // Extra details pertaining to the type of Alert recieved extends
    // upon AlertLevel providing more context
    (u8) enum AlertDescription {
        CloseNotify = 0x0,
        UnexpectedMessage = 0xA,
        BadRecordMac = 0x14,
        DecompressionFailure = 0x1E,
        IllegalParameter = 0x2F,
        HandshakeFailure = 0x28,
        NoCertificate = 0x29,
        BadCertificate = 0x2A,
        UnsupportedCertificate = 0x2B,
        CertificateRevoked = 0x2C,
        CertificateExpired = 0x2D,
        CertificateUnknown = 0x2E,
    }
}

impl Display for AlertDescription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Debug::fmt(&self, f)
    }
}

codec_enum! {
    // SSL protocol versions enum. This only contains SSLv3 because
    // thats the only protocol we implement
    (u16) enum ProtocolVersion {
        SSLv3 = 0x0300
    }
}

impl ProtocolVersion {
    /// Hard coded only supporting SSLv3 protocol version
    pub fn is_valid(&self) -> bool {
        matches!(self, ProtocolVersion::SSLv3)
    }
}

codec_enum! {
    // Cipher suites known to this application
    (u16) enum CipherSuite {
        TLS_RSA_WITH_RC4_128_SHA = 0x0005,
        TLS_RSA_WITH_RC4_128_MD5 = 0x0004
    }
}

codec_enum! {
    // Type of handshake message
    (u8) enum HandshakeType {
        ClientHello = 1,
        ServerHello = 2,
        Certificate = 11,
        ServerHelloDone = 14,
        ClientKeyExchange = 16,
        Finished = 20,
    }
}

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

/// The encoding for the certificates is the same as that of PayloadU24
/// TODO: look into merging these structs or creating a conversion.
impl Codec for Certificate {
    fn encode(&self, output: &mut Vec<u8>) {
        u24(self.0.len() as u32).encode(output);
        output.extend_from_slice(&self.0)
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let length = u24::decode(input)?.0 as usize;
        let mut reader = input.slice(length)?;
        let content = reader.remaining().to_vec();
        Some(content.into())
    }
}

/// The inner portion sized slice of the SSLRandom
pub type RandomInner = [u8; 32];

/// Structure representing a random slice of 32 bytes
#[derive(Clone)]
pub struct SSLRandom(pub RandomInner);

impl Default for SSLRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl SSLRandom {
    pub fn new() -> Self {
        let mut data: RandomInner = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut data);
        Self(data)
    }
}

impl Codec for SSLRandom {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let bytes = input.take(32)?;
        let mut opaque = [0; 32];
        opaque.copy_from_slice(bytes);
        Some(Self(opaque))
    }
}
