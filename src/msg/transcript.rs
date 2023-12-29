use super::Message;

/// Structure for keeping a record of all the message payloads that have
/// be sent and recieved. Used for computing Finished hashes. `finish` is
/// storing the ending position
#[derive(Default)]
pub struct MessageTranscript {
    /// The buffer storing all the bytes of the handshake payloads
    buffer: Vec<u8>,
    /// The index of where the transcript ended for our peer finished
    /// message
    peer_finished: usize,
}

impl MessageTranscript {
    /// Appends a raw section of bytes to the transcript
    pub fn push_raw(&mut self, message: &[u8]) {
        self.buffer.extend_from_slice(message);
    }

    /// Appends a section of bytes from the message payload to
    /// the transcript
    pub fn push_message(&mut self, message: &Message) {
        self.buffer.extend_from_slice(&message.payload)
    }

    /// Sets the ending position of the transcript for the
    ///
    pub fn end_peer(&mut self) {
        self.peer_finished = self.buffer.len();
    }

    /// Retrieves the buffer of our transcript
    pub fn current(&self) -> &[u8] {
        &self.buffer
    }

    /// Retrieves the buffer contents before the peer finished
    pub fn peer(&self) -> &[u8] {
        &self.buffer[..self.peer_finished]
    }
}
