use super::{
    codec::*,
    handshake::{HandshakeHeader, HandshakeMessage},
    Message,
};
use std::{io::ErrorKind, mem::swap};

/// Structure for joining handshake packets that are spread out across
/// multiple SSLMessages
#[derive(Default)]
pub struct HandshakeJoiner {
    /// Buffer of message payloads being accumulated
    buffer: Vec<u8>,
}

impl HandshakeJoiner {
    /// TLS allows for handshake messages of up to 16MB.  We
    /// restrict that to 64KB to limit potential for denial-of-
    /// service.
    const MAX_HANDSHAKE_SIZE: usize = 0xffff;

    /// Attempts to decode a handshake from the underlying buffer
    /// if there is one available
    pub fn next(&mut self) -> Option<std::io::Result<HandshakeMessage>> {
        // Ensure there is enough bytes for the whole header
        if self.buffer.len() < HandshakeHeader::SIZE {
            return None;
        }

        let mut reader = Reader::new(&self.buffer);

        // Try read the next available header
        let header = HandshakeHeader::try_decode(&mut reader)?;

        let length: usize = header.length.into();
        let buffer_length: usize = self.buffer.len() - HandshakeHeader::SIZE;

        // Ensure the payload is within the max size
        if length > Self::MAX_HANDSHAKE_SIZE {
            return Some(Err(std::io::Error::new(
                ErrorKind::Other,
                "Message payload too large",
            )));
        }

        // Buffer isn't large enough
        if buffer_length < length {
            return None;
        }

        // Creates the message payload by splitting off the length of the read portion
        // and swapping the underlying buffer
        let payload = {
            // Temp store the unread portion of the buffer
            let mut tmp = self.buffer.split_off(length + HandshakeHeader::SIZE);
            // Swap the unread buffer with the read buffer
            swap(&mut tmp, &mut self.buffer);
            tmp
        };

        Some(Ok(HandshakeMessage {
            ty: header.ty,
            payload,
        }))
    }

    /// Consumes the provided message into the buffer attempting to
    /// decode a handshake from the newly extended buffer
    ///
    /// # Arguments
    /// * msg - The message to consume the payload of
    pub fn consume(&mut self, msg: Message) {
        // Most of the time payloads will take the entire buffer
        // so we can just set the buffer to the first message
        // payload if the buffer is empty
        if self.buffer.is_empty() {
            self.buffer = msg.payload;
        } else {
            self.buffer.extend_from_slice(&msg.payload);
        }
    }
}
