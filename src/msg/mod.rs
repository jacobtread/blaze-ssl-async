use self::{
    codec::{Codec, Reader},
    types::{AlertDescription, AlertLevel, MessageType, ProtocolVersion},
};
use std::fmt::Display;

pub mod codec;
pub mod deframer;
pub mod handshake;
pub mod joiner;
pub mod transcript;
pub mod types;

/// Structure representing a SSLMessage where the contents are
/// SSLPlaintext and are able to be decoded to the known message
/// type stored along-side the payload
pub struct Message {
    /// The type of message this message is
    pub message_type: MessageType,
    /// The protocol version of the message
    pub protocol_version: ProtocolVersion,
    /// The plain-text payload bytes
    pub payload: Vec<u8>,
}

impl Message {
    /// Maximum allowed fragment payload size
    const MAX_PAYLOAD_SIZE: usize = 16384 + 2048;

    /// Size of Message Type + Version + Length
    const HEADER_SIZE: usize = 1 + 2 + 2;

    /// Maximum allowed on-wire message size
    const MAX_WIRE_SIZE: usize = Self::HEADER_SIZE + Self::MAX_PAYLOAD_SIZE;

    /// Maximum length each fragment can be
    const MAX_FRAGMENT_LENGTH: usize = 16384;

    /// Provides the size in bytes of the message
    pub fn size(&self) -> usize {
        Self::HEADER_SIZE + self.payload.len()
    }

    /// Creates a new message for the provided `message_type` and
    /// `payload`. Always sets the protocol version to SSLv3
    #[inline]
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Self {
        Self {
            protocol_version: ProtocolVersion::SSLv3,
            message_type,
            payload,
        }
    }

    /// Fragments the message into smaller messages that are
    /// no greater than [Self::MAX_FRAGMENT_LENGTH] in size
    pub fn fragment(&self) -> impl Iterator<Item = Message> + '_ {
        self.payload
            .chunks(Self::MAX_FRAGMENT_LENGTH)
            .map(move |payload| Message {
                message_type: self.message_type,
                protocol_version: self.protocol_version,
                payload: payload.to_vec(),
            })
    }
}

impl Codec for Message {
    fn encode(self, output: &mut Vec<u8>) {
        let length = self.payload.len();

        // Sanity check for payload length bounds
        debug_assert!(length <= u16::MAX as usize);

        // Reserve the message space ahead of time
        output.reserve(Self::HEADER_SIZE + length);

        self.message_type.encode(output);
        self.protocol_version.encode(output);
        (length as u16).encode(output);
        output.extend_from_slice(&self.payload);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let message_type: MessageType = MessageType::decode(input)?;
        let protocol_version: ProtocolVersion = ProtocolVersion::decode(input)?;
        let length: u16 = u16::decode(input)?;
        let payload = input.take(length as usize)?;
        let payload = payload.to_vec();

        Some(Self {
            message_type,
            protocol_version,
            payload,
        })
    }
}

/// Alert message type which contains an alert level and description
/// used to handle errors and warnings
#[derive(Debug, Clone, Copy)]
pub(crate) struct AlertError {
    /// The level of the alert
    pub level: AlertLevel,
    /// The alert description
    pub description: AlertDescription,
}

impl From<AlertError> for std::io::Error {
    fn from(value: AlertError) -> Self {
        std::io::Error::new(std::io::ErrorKind::Other, value)
    }
}

impl AlertError {
    /// Creates a new fatal alert message ith the provided
    /// `description`
    #[inline]
    pub fn fatal(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }

    /// Creates a new warning alert message ith the provided
    /// `description`
    #[inline]
    pub fn warning(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::Warning,
            description,
        }
    }

    /// Reads an alert message from the provided `message` will
    /// return a fatal level and illegal parameter description
    /// if the reading fails.
    pub fn from_message(message: &Message) -> Self {
        // Attempt to read the message
        let mut reader = Reader::new(&message.payload);
        AlertError::decode(&mut reader)
            // Invalid messages use default illegal param
            .unwrap_or(Self::fatal(AlertDescription::IllegalParameter))
    }
}

impl Codec for AlertError {
    fn encode(self, output: &mut Vec<u8>) {
        self.level.encode(output);
        self.description.encode(output);
    }

    fn decode(input: &mut Reader) -> Option<Self> {
        let level = AlertLevel::decode(input)?;
        let description = AlertDescription::decode(input)?;
        Some(Self { level, description })
    }
}

impl Display for AlertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "{:?} alert: {:?}",
            self.level, self.description
        ))
    }
}

impl std::error::Error for AlertError {}
