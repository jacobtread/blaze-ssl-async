use super::{codec::Reader, Message, MessageError};
use std::{
    collections::VecDeque,
    io::ErrorKind,
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

        Poll::Ready(Ok(()))
    }

    /// Attempts to decode messages from the underlying buffer. Will
    /// return an [Err] in cases were it cannot recover otherwise will
    /// return [Ok] when deframing has completed/can be continue
    pub fn deframe(&mut self) -> std::io::Result<()> {
        let mut reader: Reader;
        loop {
            // Create a reader over the used portion of the buffer
            reader = Reader::new(&self.buffer[..self.used]);

            let msg: Message = match Message::decode(&mut reader) {
                Ok(msg) => msg,
                Err(err) => match err {
                    // Not enough bytes for the next message wait for more bytes
                    MessageError::TooShort => return Ok(()),
                    // Stream is invalid terminate connection
                    MessageError::IllegalVersion => {
                        return Err(std::io::Error::new(
                            ErrorKind::Other,
                            "Unsupported SSL version",
                        ))
                    }
                },
            };

            let cursor = reader.cursor();
            self.messages.push_back(msg);

            if cursor < self.used {
                // Move the data past the cursor to the start of
                // the buffer
                self.buffer.copy_within(cursor..self.used, 0);
                self.used -= cursor;
            } else {
                self.used = 0;
            }
        }
    }
}
