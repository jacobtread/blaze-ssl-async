use super::{codec::Reader, Message, MessageError};
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{self, AsyncRead, ReadBuf};

/// Structure for decoding SSLMessages from multiple Reads because
/// the entire fragment content may not be available on the first
/// read. When full messages are available they are pushed to the
/// `messages` queue where they are consumed.
pub struct MessageDeframer {
    /// Queue of messages that have been parsed
    messages: VecDeque<Message>,
    /// The buffer containing the incomplete message fragments
    buffer: Box<[u8; Message::MAX_WIRE_SIZE]>,
    /// The amount of the buffer that has been used
    used: usize,
}

impl MessageDeframer {
    /// Consturctor function for creating a new MessageDeframer
    pub fn new() -> Self {
        Self {
            messages: VecDeque::new(),
            buffer: Box::new([0u8; Message::MAX_WIRE_SIZE]),
            used: 0,
        }
    }

    /// Attempts to take the next message that has been decoded
    /// from the queue. If there are non this returns None
    pub fn next(&mut self) -> Option<Message> {
        self.messages.pop_front()
    }

    /// Reads from the provided `read` source attempting to decode
    /// messages from the new buffer data along with existing.
    /// returns true if everything went okay and false if the data
    /// inside the buffer was invalid
    ///
    /// `cx`   The polling context
    /// `read` The readable input
    pub fn poll_read<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        read: Pin<&mut R>,
    ) -> Poll<io::Result<bool>> {
        let mut read_buf = ReadBuf::new(&mut self.buffer[self.used..]);
        try_ready!(read.poll_read(cx, &mut read_buf));
        self.used += read_buf.filled().len();
        let mut reader;
        loop {
            reader = Reader::new(&self.buffer[..self.used]);
            match Message::decode(&mut reader) {
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
                Err(MessageError::IllegalVersion) => return Poll::Ready(Ok(false)),
            }
        }
        Poll::Ready(Ok(true))
    }
}
