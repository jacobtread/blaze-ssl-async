use std::collections::VecDeque;
use super::{Message, HandshakePayload, u24, Reader};

/// Structure of a handshake that was joined by the Handshake joiner. This
/// structure includes the full length payload that was decoded from so that
/// this message can be transcribed properly
#[derive(Debug)]
pub struct JoinedHandshake {
    /// The decoded handshake payload
    pub handshake: HandshakePayload,
    /// The bytes of the payload that the handshake was formed from
    pub payload: Vec<u8>

}

/// Structure for joining handshake packets that are spread out across
/// multiple SSLMessages
pub struct HandshakeJoiner {
    /// Joined handshakes output buffer
    handshakes: VecDeque<JoinedHandshake>,
    /// Buffer of message payloads being accumulated
    buffer: Vec<u8>,
}

impl HandshakeJoiner {

    /// Required bytes to obtain the header of a handshake
    /// Handshake type + Handshake Length
    const HEADER_SIZE: usize = 1 + 3;

    /// TLS allows for handshake messages of up to 16MB.  We
    /// restrict that to 64KB to limit potential for denial-of-
    /// service.
    const MAX_HANDSHAKE_SIZE: usize = 0xffff;


    /// Creates a new handshake joiner
    pub fn new() -> Self {
        Self {
            handshakes: VecDeque::new(),
            buffer: Vec::new()
        }
    }

    /// Attempts to take the next available joined handshake
    /// if there is one otherwise its None
    pub fn next(&mut self) -> Option<JoinedHandshake> {
        self.handshakes.pop_front()
    }

    /// Consumes the provided message into the buffer attempting to
    /// decode a handshake from the newly extended buffer
    pub fn consume(&mut self, msg: Message) {
        // Most of the time payloads will take the entire buffer
        // so we can just set the buffer to the first message
        // payload if the buffer is empty
        if self.buffer.is_empty() {
            self.buffer = msg.payload;
        } else {
            self.buffer.extend_from_slice(&msg.payload);
        }

        loop {
            if self.buffer.len() < Self::HEADER_SIZE {
                break;
            }

            let (header, rest) = &self.buffer.split_at(Self::HEADER_SIZE);
            let length = match u24::from_bytes(&header[1..]) {
                Some(len) => len.0 as usize,
                None => break,
            };

            if length > Self::MAX_HANDSHAKE_SIZE || rest.get(..length).is_none() {
                break;
            }

            let mut reader = Reader::new(&self.buffer);
            let handshake = match HandshakePayload::decode(&mut reader) {
                Some(payload) => payload,
                None => break
            };

            let length = reader.cursor();
            let payload = self.buffer[0..length].to_vec();

            self.handshakes.push_back(JoinedHandshake { handshake, payload });
            self.buffer = self.buffer.split_off(length);
        }
    }

}