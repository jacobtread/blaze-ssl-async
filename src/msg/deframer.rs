use super::{
    codec::{Codec, Reader},
    Message,
};
use std::{
    collections::VecDeque,
    pin::Pin,
    task::{ready, Context, Poll},
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
    /// from the queue. If there are non this returns [None]
    pub fn next(&mut self) -> Option<Message> {
        self.messages.pop_front()
    }

    /// Polls reading bytes from the provided `read` into the
    /// buffer stored on this deframer and increases the used
    /// counter
    pub fn poll_read<R>(&mut self, read: &mut R, cx: &mut Context<'_>) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
    {
        let read = Pin::new(read);

        // Create a read buffer over our buffer unused portion
        let mut buf = ReadBuf::new(&mut self.buffer[self.used..]);

        // Poll reading from reader
        ready!(read.poll_read(cx, &mut buf))?;

        // Increase the amount of the buffer thats been used
        self.used += buf.filled().len();

        // Attempt to deframe messages
        self.decode();

        Poll::Ready(Ok(()))
    }

    /// Creates a reader over the filled portion of the buffer
    #[inline]
    fn reader(&self) -> Reader {
        Reader::new(&self.buffer[..self.used])
    }

    /// Attempts to decode messages from the underlying buffer
    fn decode(&mut self) {
        while let Some(msg) = Message::decode(&mut self.reader()) {
            // Size of the message removed from the buffer
            let consumed_size = msg.size();

            // Store the decoded message
            self.messages.push_back(msg);

            // If the whole buffer wasn't read move the unread bytes over
            if consumed_size < self.used {
                // Move the data past the cursor to the start of
                // the buffer
                self.buffer.copy_within(consumed_size..self.used, 0);
            }

            // Decreased the used potion of the buffer
            self.used -= consumed_size;
        }
    }
}
