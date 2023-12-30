use super::{codec::*, types::*, Message};

/// Different types of payloads that can be stored within handshake
/// messages. Names match up with the name for the type of message
pub enum HandshakePayload {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    Certificate(CertificateChain),
    ServerHelloDone(ServerHelloDone),
    ClientKeyExchange(OpaqueBytes),
    Finished(Finished),
    Unknown(u8, OpaqueBytes),
}

/// From implementation for converting handshake payloads into
/// handshake messages by encoding the contents
impl From<HandshakePayload> for Message {
    fn from(value: HandshakePayload) -> Self {
        Message {
            message_type: MessageType::Handshake,
            payload: value.encode(),
        }
    }
}

impl HandshakePayload {
    /// Converts this payload into the handshake type for the
    /// specific payload.
    fn handshake_type(&self) -> HandshakeType {
        match self {
            Self::ClientHello(_) => HandshakeType::ClientHello,
            Self::ServerHello(_) => HandshakeType::ServerHello,
            Self::Certificate(_) => HandshakeType::Certificate,
            Self::ServerHelloDone(_) => HandshakeType::ServerHelloDone,
            Self::ClientKeyExchange(_) => HandshakeType::ClientKeyExchange,
            Self::Finished(_) => HandshakeType::Finished,
            Self::Unknown(ty, _) => HandshakeType::Unknown(*ty),
        }
    }

    /// Encodes the inner payload of this message and creates a handshake
    /// message from the contents returning the bytes of the handshake message
    fn encode(&self) -> Vec<u8> {
        let content = &mut Vec::new();
        match self {
            Self::ClientHello(payload) => payload.encode(content),
            Self::ServerHello(payload) => payload.encode(content),
            Self::Certificate(payload) => payload.encode(content),
            Self::ServerHelloDone(payload) => payload.encode(content),
            Self::ClientKeyExchange(payload) => payload.encode(content),
            Self::Finished(payload) => payload.encode(content),
            Self::Unknown(_, payload) => payload.encode(content),
        }
        let content_length = content.len();
        let mut output = Vec::with_capacity(content_length + 4);
        let length = u24(content_length as u32);
        let ty = self.handshake_type();
        ty.encode(&mut output);
        length.encode(&mut output);
        output.append(content);
        output
    }

    /// Decodes a handshake payload from the provided reader based
    /// on the type flag
    ///
    /// `reader` The reader to decode from
    pub fn decode(reader: &mut Reader) -> Option<Self> {
        let ty: HandshakeType = HandshakeType::decode(reader)?;
        let length: usize = u24::decode(reader)?.0 as usize;
        let input: &mut Reader = &mut reader.slice(length)?;
        Some(match ty {
            HandshakeType::ClientHello => Self::ClientHello(Codec::decode(input)?),
            HandshakeType::ServerHello => Self::ServerHello(Codec::decode(input)?),
            HandshakeType::Certificate => Self::Certificate(Codec::decode(input)?),
            HandshakeType::ServerHelloDone => Self::ServerHelloDone(Codec::decode(input)?),
            HandshakeType::ClientKeyExchange => Self::ClientKeyExchange(Codec::decode(input)?),
            HandshakeType::Finished => Self::Finished(Codec::decode(input)?),
            HandshakeType::Unknown(value) => Self::Unknown(value, Codec::decode(input)?),
        })
    }
}

/// Message for SSL clients from their intitial hello message which
/// contains the random number slice to use and the cipher suites
/// the client has available.
pub struct ClientHello {
    /// The client random number
    pub random: SSLRandom,
    /// The client available cipher suites
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
        // Protocol version of this message is ignored
        let _: ProtocolVersion = ProtocolVersion::decode(input)?;
        let random: SSLRandom = SSLRandom::decode(input)?;
        // Session logic not implemented so this is ignored
        let _: Vec<u8> = decode_vec_u8(input)?;
        let cipher_suites: Vec<CipherSuite> = decode_vec_u16(input)?;
        // Compression methods ignored
        let _: Vec<u8> = decode_vec_u8::<u8>(input)?;

        Some(ClientHello {
            random,
            cipher_suites,
        })
    }
}

/// Message for SSL servers for their hello message in response to
/// a client hello which contains the server random number and the
/// chosen cipher suite
pub struct ServerHello {
    /// The server random number
    pub random: SSLRandom,
    /// The chosen cipher suite
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
        // Ignored protocol version
        let _: ProtocolVersion = ProtocolVersion::decode(input)?;
        let random: SSLRandom = SSLRandom::decode(input)?;
        // Ignored session ID
        let _: Vec<u8> = decode_vec_u8(input)?;
        let cipher_suite: CipherSuite = CipherSuite::decode(input)?;
        // Ignored compression value
        let _: u8 = input.take_byte()?;

        Some(Self {
            random,
            cipher_suite,
        })
    }
}

/// Collection of certificates
pub struct CertificateChain(pub(crate) Vec<Certificate>);

impl Codec for CertificateChain {
    fn encode(&self, output: &mut Vec<u8>) {
        encode_vec_u24(output, &self.0);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        decode_vec_u24::<Certificate>(input).map(Self)
    }
}

/// Message for the server to indicate its hello is
/// done and has no more hello messages
pub struct ServerHelloDone;

impl Codec for ServerHelloDone {
    fn encode(&self, _output: &mut Vec<u8>) {}
    fn decode(_input: &mut Reader) -> Option<Self> {
        Some(Self)
    }
}

/// Structure of a set of bytes where the contents are
/// not known without additional context. Used for unknown packets
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

/// Finished method used by both the client and server
/// to exchange hashes of the message transcript to
/// ensure everything matches
#[derive(Debug, PartialEq, Eq)]
pub struct Finished {
    /// MD5 hash of the transcript
    pub md5_hash: [u8; 16],
    /// SHA1 hash of the transcript
    pub sha1_hash: [u8; 20],
}

impl Codec for Finished {
    fn encode(&self, output: &mut Vec<u8>) {
        output.extend_from_slice(&self.md5_hash);
        output.extend_from_slice(&self.sha1_hash);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let md5_hash: [u8; 16] = input.take_fixed()?;
        let sha1_hash: [u8; 20] = input.take_fixed()?;

        Some(Self {
            md5_hash,
            sha1_hash,
        })
    }
}
