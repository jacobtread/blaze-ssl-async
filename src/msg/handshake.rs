use std::fmt;

use crate::msg::types::ProtocolVersion;

use super::{
    decode_vec_u16, decode_vec_u24, decode_vec_u8, encode_vec_u16, encode_vec_u24, encode_vec_u8,
    Certificate, CipherSuite, Codec, HandshakeType, Reader, SSLRandom, u24, Message, MessageType
};

#[derive(Debug)]
pub enum HandshakePayload {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(ServerCertificate),
    ServerHelloDone(ServerHelloDone),
    ClientKeyExchange(OpaqueBytes),
    Finished(Finished),
    Unknown(u8, OpaqueBytes),
}

impl HandshakePayload {

    /// Returns the type of handshake this is
    pub fn handshake_type(&self) -> HandshakeType {
        match self {
            Self::ClientHello(_) => HandshakeType::ClientHello,
            Self::ServerHello(_) => HandshakeType::ServerHello,
            Self::Certificate(_) => HandshakeType::Certificate,
            Self::ServerHelloDone(_) => HandshakeType::ServerHelloDone,
            Self::ClientKeyExchange(_) => HandshakeType::ClientKeyExchange,
            Self::Finished(_) => HandshakeType::Finished,
            Self::Unknown(ty,_) => HandshakeType::Unknown(*ty),
        }
    }

    /// Converts this payload into a message by encoding it
    pub fn as_message(&self) -> Message {
        let payload = self.encode();
        Message {
            message_type: MessageType::Handshake,
            payload
        }
    }

    fn encode(&self) -> Vec<u8> {
        let mut content = Vec::new();
        match self {
            Self::ClientHello(payload) => payload.encode(&mut content),
            Self::ServerHello(payload) => payload.encode(&mut content),
            Self::Certificate(payload) =>  payload.encode(&mut content),
            Self::ServerHelloDone(payload) => payload.encode(&mut content),
            Self::ClientKeyExchange(payload) => payload.encode(&mut content),
            Self::Finished(payload) =>  payload.encode(&mut content),

            Self::Unknown(ty, payload) => {
                ty.encode(&mut content);
                payload.encode(&mut content);
            }
        }

        let mut output = Vec::with_capacity(content.len() + 4);
        let length = u24(content.len() as u32);
        let ty = self.handshake_type();
        ty.encode(&mut output);
        length.encode(&mut output);
        output.append(&mut content);
        output
    }

    pub(crate) fn decode(input: &mut Reader) -> Option<Self> {
        let ty = HandshakeType::decode(input)?;
        let length = u24::decode(input)?.0 as usize;
        let mut input = input.slice(length)?;
        Some(match ty {
            HandshakeType::ClientHello => {
                HandshakePayload::ClientHello(ClientHello::decode(&mut input)?)
            }
            HandshakeType::ServerHello => {
                HandshakePayload::ServerHello(ServerHello::decode(&mut input)?)
            }
            HandshakeType::Certificate => {
                HandshakePayload::Certificate(ServerCertificate::decode(&mut input)?)
            }
            HandshakeType::ServerHelloDone => {
                HandshakePayload::ServerHelloDone(ServerHelloDone::decode(&mut input)?)
            }
            HandshakeType::ClientKeyExchange => {
                HandshakePayload::ClientKeyExchange(OpaqueBytes::decode(&mut input)?)
            }
            HandshakeType::Finished => {
                HandshakePayload::Finished(Finished::decode(&mut input)?)
            }
            HandshakeType::Unknown(value) => {
                HandshakePayload::Unknown(value, OpaqueBytes::decode(&mut input)?)
            }
        })
    }
}

#[derive(Debug)]
pub struct ClientHello {
    pub random: SSLRandom,
    pub cipher_suites: Vec<CipherSuite>,
}

impl Codec for ClientHello {
    fn encode(&self, output: &mut Vec<u8>) {
        // Always SSLv3 protocol version
        ProtocolVersion::SSLv3.encode(output);
        self.random.encode(output);
        // Hardcoded empty Session ID (Don't support resumption)
        output.push(0);
        encode_vec_u16::<CipherSuite>(output, &self.cipher_suites);
        // Null compression
        encode_vec_u8::<u8>(output, &[0]);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let _protocol_version = ProtocolVersion::decode(input)?;
        let random = SSLRandom::decode(input)?;
        let _session_id = decode_vec_u8::<u8>(input)?;
        let cipher_suites = decode_vec_u16::<CipherSuite>(input)?;
        let _compression_methods = decode_vec_u8::<u8>(input)?;

        Some(ClientHello {
            random,
            cipher_suites,
        })
    }
}

#[derive(Debug)]
pub struct ServerHello {
    pub random: SSLRandom,
    pub cipher_suite: CipherSuite,
}

impl Codec for ServerHello {
    fn encode(&self, output: &mut Vec<u8>) {
        // Always SSLv3 protocol version
        ProtocolVersion::SSLv3.encode(output);
        self.random.encode(output);
        // Hardcoded empty Session ID (Don't support resumption)
        output.push(0);
        self.cipher_suite.encode(output);
        // Null compression
        output.push(0);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let _protocol_version = ProtocolVersion::decode(input)?;
        let random = SSLRandom::decode(input)?;
        let _session_id = decode_vec_u8::<u8>(input)?;
        let cipher_suite = CipherSuite::decode(input)?;
        let _compression_method = input.take_byte()?;

        Some(Self {
            random,
            cipher_suite,
        })
    }
}

#[derive(Debug)]
pub struct ServerCertificate {
    pub certificates: Vec<Certificate>,
}

impl Codec for ServerCertificate {
    fn encode(&self, output: &mut Vec<u8>) {
        encode_vec_u24(output, &self.certificates);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let certificates = decode_vec_u24::<Certificate>(input)?;
        Some(Self { certificates })
    }
}

pub struct ServerHelloDone;

impl fmt::Debug for ServerHelloDone {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServerHelloDone")
    }
}

impl Codec for ServerHelloDone {
    fn encode(&self, _output: &mut Vec<u8>) {}
    fn decode(_input: &mut Reader) -> Option<Self> {
        Some(Self)
    }
}

#[derive(Debug)]
pub struct OpaqueBytes(pub Vec<u8>);

impl Codec for OpaqueBytes {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.0)
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let bytes = input.remaining().to_vec();
        Some(Self(bytes))
    }
}

#[derive(Debug)]
pub struct Finished {
    pub md5_hash: [u8; 16],
    pub sha_hash: [u8; 20],
}

impl Codec for Finished {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.md5_hash);
        output.extend_from_slice(&self.sha_hash);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let mut md5_hash = [0u8; 16];
        md5_hash.copy_from_slice(&input.take(16)?);
        let mut sha_hash = [0u8; 20];
        sha_hash.copy_from_slice(&input.take(20)?);
        Some(Self { md5_hash, sha_hash })
    }
}
