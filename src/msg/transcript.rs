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
    /// Appends the provided `message` bytes to the transcript
    #[inline]
    pub fn append(&mut self, message: &[u8]) {
        self.buffer.extend_from_slice(message);
    }

    /// Sets the ending position of the transcript for the peer
    #[inline]
    pub fn finish_peer(&mut self) {
        self.peer_finished = self.buffer.len();
    }

    /// Retrieves the buffer of our transcript
    #[inline]
    pub fn current(&self) -> &[u8] {
        &self.buffer
    }

    /// Retrieves the buffer contents before the peer finished
    #[inline]
    pub fn peer(&self) -> &[u8] {
        &self.buffer[..self.peer_finished]
    }
}
