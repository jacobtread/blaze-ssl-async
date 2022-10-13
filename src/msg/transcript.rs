use super::Message;

/// Structure for keeping a record of all the message payloads that have
/// be sent and recieved. Used for computing Finished hashes. `finish` is
/// storing the ending position
#[derive(Debug)]
pub struct MessageTranscript {
    buffer: Vec<u8>,
    end: usize,
}

impl MessageTranscript {
    /// Creates a new message transcript
    pub fn new() -> Self {
        Self {
            buffer: Vec::new(),
            end: 0
        }
    }

    /// Appends a raw section of bytes to the transcript
    pub fn push_raw(&mut self, message: &[u8]) {
        self.buffer.extend_from_slice(message);
    }

    /// Appends a section of bytes from the message payload to
    /// the transcript
    pub fn push_message(&mut self, message: &Message) {
        self.buffer.extend_from_slice(&message.payload)
    }

    /// Sets the ending position to the end of the current
    /// transcript
    pub fn finish(&mut self) {
        self.end = self.buffer.len();
    }

    /// Retrieves the entire buffer up to the most recent data
    pub fn current(&self) -> &[u8] {
        &self.buffer
    }

    /// Retrieves the buffer contents before `finish` was called
    pub fn last(&self) -> &[u8] {
        &self.buffer[..self.end]
    }
}
