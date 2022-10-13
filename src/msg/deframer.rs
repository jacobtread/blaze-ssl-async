use std::collections::VecDeque;
use crate::msg::{OpaqueMessage, MessageError, Reader};
use std::io::{self, Read};

/// Structure for decoding SSLMessages from multiple Reads because
/// the entire fragment content may not be available on the first
/// read. When full messages are available they are pushed to the
/// `messages` queue where they are consumed.
pub struct MessageDeframer {
    /// Queue of messages that have been parsed
    messages: VecDeque<OpaqueMessage>,
    /// The buffer containing the incomplete message fragments
    buffer: Box<[u8; OpaqueMessage::MAX_WIRE_SIZE]>,
    /// The amount of the buffer that has been used
    used: usize,
}

impl MessageDeframer {

    /// Consturctor function for creating a new MessageDeframer
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            buffer: Box::new([0u8; OpaqueMessage::MAX_WIRE_SIZE]),
            used: 0
        }
    }

    /// Attempts to take the next message that has been decoded
    /// from the queue. If there are non this returns None
    pub fn next(&mut self) -> Option<OpaqueMessage> {
        self.messages.pop_front()
    }

    /// Reads from the provided `read` source attempting to decode
    /// messages from the new buffer data along with existing.
    /// returns true if everything went okay and false if the data
    /// inside the buffer was invalid
    pub fn read(&mut self, read: &mut dyn Read) -> io::Result<bool> {
        self.used += read.read(&mut self.buffer[self.used..])?;
        let mut reader;
        loop {
            reader = Reader::new(&self.buffer[..self.used]);
            match OpaqueMessage::decode(&mut reader) {
                Ok(message) => {
                    let used = reader.cursor();
                    self.messages.push_back(message);

                    // Consume the buffer
                    if used < self.used {
                        self.buffer.copy_within(used..self.used, 0);
                        self.used -= used;
                    } else {
                        self.used = 0;
                    }
                }
                Err(MessageError::TooShort) => break,
                Err(MessageError::IllegalVersion) => return Ok(false)
            }
        }
        Ok(true)
    }
}