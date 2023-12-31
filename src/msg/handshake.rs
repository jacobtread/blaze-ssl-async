use super::{codec::*, types::*, AlertError, Message};

/// Header details for a handshake, contains the type of handshake
/// and the length of the handshake payload
pub struct HandshakeHeader {
    /// Type of handshake
    pub ty: HandshakeType,
    /// Length of the handshake payload
    pub length: u24,
}

impl HandshakeHeader {
    /// Size in bytes of the header
    pub const SIZE: usize = 4;

    /// Attempts to decode a handshake header from the provided `reader`
    pub fn try_decode(reader: &mut Reader) -> Option<Self> {
        let ty: HandshakeType = HandshakeType::decode(reader)?;
        let length: u24 = u24::decode(reader)?;

        Some(Self { ty, length })
    }
}

/// Handshake message, contains the type and the payload
/// for the handshake message
pub struct HandshakeMessage {
    /// The type of the message
    pub ty: HandshakeType,
    /// The message payload, includes the encoded type and
    /// length fields of the actual message
    pub payload: Vec<u8>,
}

impl From<HandshakeMessage> for Message {
    fn from(value: HandshakeMessage) -> Self {
        Message {
            message_type: MessageType::Handshake,
            protocol_version: ProtocolVersion::SSLv3,
            payload: value.payload,
        }
    }
}

impl HandshakeMessage {
    pub fn new<T>(ty: HandshakeType, value: T) -> Self
    where
        T: Codec,
    {
        let mut payload: Vec<u8> = Vec::new();

        // Encode the type of message into the payload
        ty.encode(&mut payload);

        // Store the length before the placeholder length
        let length_offset: usize = payload.len();

        // Encode a placeholder length for the value
        payload.extend_from_slice(&[0; 3]);

        // Encode the actual value
        value.encode(&mut payload);

        // Get the length of the encoded content
        let content_length: usize = payload.len() - HandshakeHeader::SIZE;
        let content_length: u24 = u24::from(content_length);

        // Rewind and update the length
        rewind_write(&mut payload, length_offset, |payload| {
            content_length.encode(payload)
        });

        Self { ty, payload }
    }

    pub fn expect_type<T>(&self, ty: HandshakeType) -> Result<T, AlertError>
    where
        T: Codec,
    {
        if ty != self.ty {
            // Got an unexpected message
            return Err(AlertError::fatal(AlertDescription::UnexpectedMessage));
        }

        // Try decode the handshake payload
        let value = self
            .try_decode()
            // Handle decode failure
            .ok_or(AlertError::fatal(AlertDescription::IllegalParameter))?;

        Ok(value)
    }

    /// Attempts to decode the handshake payload as the provided type
    pub fn try_decode<T>(&self) -> Option<T>
    where
        T: Codec,
    {
        let mut reader = Reader::new(&self.payload[HandshakeHeader::SIZE..]);
        T::decode(&mut reader)
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
    fn encode(self, output: &mut Vec<u8>) {
        // Always SSLv3 protocol version
        ProtocolVersion::SSLv3.encode(output);
        self.random.encode(output);
        // Hardcoded empty Session ID (Don't support resumption)
        output.push(0);
        encode_vec::<u16, CipherSuite>(output, self.cipher_suites);
        // Null compression
        encode_vec::<u8, u8>(output, vec![0]);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        // Protocol version of this message is ignored
        let _: ProtocolVersion = ProtocolVersion::decode(input)?;
        let random: SSLRandom = SSLRandom::decode(input)?;
        // Session logic not implemented so this is ignored
        let _: Vec<u8> = decode_vec::<u8, u8>(input)?;
        let cipher_suites: Vec<CipherSuite> = decode_vec::<u16, CipherSuite>(input)?;
        // Compression methods ignored
        let _: Vec<u8> = decode_vec::<u8, u8>(input)?;

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
    fn encode(self, output: &mut Vec<u8>) {
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
        let _: Vec<u8> = decode_vec::<u8, u8>(input)?;
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
    fn encode(self, output: &mut Vec<u8>) {
        encode_vec::<u24, Certificate>(output, self.0);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        decode_vec::<u24, Certificate>(input).map(Self)
    }
}

/// Message for the server to indicate its hello is
/// done and has no more hello messages
pub struct ServerHelloDone;

impl Codec for ServerHelloDone {
    fn encode(self, _output: &mut Vec<u8>) {}
    fn decode(_input: &mut Reader) -> Option<Self> {
        Some(Self)
    }
}

/// Structure of a set of bytes where the contents are
/// not known without additional context. Used for unknown packets
pub struct OpaqueBytes(pub Vec<u8>);

impl Codec for OpaqueBytes {
    fn encode(self, output: &mut Vec<u8>) {
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
    fn encode(self, output: &mut Vec<u8>) {
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
