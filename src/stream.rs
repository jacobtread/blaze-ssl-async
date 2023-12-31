//! SSL Stream wrapper around the tokio [TcpStream]
//!
//! ```rust,no_run
//! // BlazeStream is a wrapper over tokio TcpStream
//! use blaze_ssl_async::BlazeStream;
//!
//! // Tokio read write extensions used for read_exact and write_all
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     // BlazeStream::connect takes in any value that implements ToSocketAddrs
//!     // some common implementations are "HOST:PORT" and ("HOST", PORT)
//!     let mut stream = BlazeStream::connect(("159.153.64.175", 42127)).await?;
//!
//!     // TODO... Read from the stream as you would a normal TcpStream
//!     let mut buf = [0u8; 12];
//!     stream.read_exact(&mut buf).await?;
//!     // Write the bytes back
//!     stream.write_all(&buf).await?;
//!     // You **MUST** flush BlazeSSL streams or else the data will never
//!     // be sent to the client (Attempt to read will automatically flush)
//!     stream.flush().await?;
//!
//!     Ok(())
//! }
//! ```
//!
use super::{
    crypto::rc4::*,
    msg::{codec::*, deframer::MessageDeframer, types::*, AlertError, Message},
};
use crate::{handshake::Handshaking, listener::BlazeServerContext};
use std::{
    cmp,
    io::{self, ErrorKind},
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpStream, ToSocketAddrs},
};

/// Wrapper around [TcpStream] providing SSL encryption
pub struct BlazeStream {
    /// Underlying stream target
    stream: TcpStream,

    /// Message deframer for de-framing messages from the read stream
    deframer: MessageDeframer,

    /// Decryptor for decrypting messages if the stream is encrypted
    pub(crate) decryptor: Option<Rc4Decryptor>,
    /// Encryptor for encrypting messages if the stream should be encrypted
    pub(crate) encryptor: Option<Rc4Encryptor>,

    /// Buffer for input that is read from the application layer
    app_read_buffer: Vec<u8>,
    /// Buffer for output written to the application layer
    /// (Written to stream when connection is flushed)
    app_write_buffer: Vec<u8>,

    /// Buffer for the raw packet contents that are going to be
    /// written to the stream
    write_buffer: Vec<u8>,

    /// State determining whether the stream is stopped
    pub(crate) stopped: bool,
}

impl BlazeStream {
    /// Connects to a remote address creating a client blaze stream
    /// to that address.
    ///
    /// # Arguments
    /// * `addr` - The address to connect to
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        let mut stream = Self::new(stream);

        // Complete the client handshake
        if let Err(err) = Handshaking::create_client(&mut stream).await {
            // Ensure the stream is correctly flushed and shutdown on error
            _ = stream.shutdown().await;
            return Err(err);
        }

        Ok(stream)
    }

    /// Accepts the connection of `stream` as a client connected
    /// to a server using the provided `data`
    ///
    /// ## Arguments
    /// * `context` - The server context to use
    pub async fn accept(
        stream: TcpStream,
        context: Arc<BlazeServerContext>,
    ) -> std::io::Result<Self> {
        let mut stream = Self::new(stream);

        // Complete the server handshake
        if let Err(err) = Handshaking::create_server(&mut stream, context).await {
            // Ensure the stream is correctly flushed and shutdown on error
            _ = stream.shutdown().await;
            return Err(err);
        }

        Ok(stream)
    }

    /// Returns a reference to the underlying stream
    pub fn get_ref(&self) -> &TcpStream {
        &self.stream
    }

    /// Returns a mutable reference to the underlying stream
    pub fn get_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    /// Returns the underlying stream that this BlazeStream
    /// is wrapping
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }

    /// Wraps the provided `stream` with a [BlazeStream] preparing
    /// it to be used with a handshake state
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            deframer: MessageDeframer::new(),
            decryptor: None,
            encryptor: None,
            app_write_buffer: Vec::new(),
            app_read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            stopped: false,
        }
    }

    /// Polls for the next message to be recieved. Decryptes encrypted messages
    /// and handles alert messages.
    ///
    /// # Arguments
    /// * cx - The polling context
    pub(crate) fn poll_next_message(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<Message>> {
        loop {
            if let Some(mut message) = self.deframer.next() {
                // Decrypt message if encryption is enabled
                self.try_decrypt_message(&mut message)?;
                return Poll::Ready(Ok(message));
            }

            // Poll reading data from the stream
            ready!(self.deframer.poll_read(&mut self.stream, cx))?;

            // Attempt to deframe messages from the stream
            if let Err(err) = self.deframer.deframe() {
                // Write the error alert message
                self.write_alert(AlertError::fatal(AlertDescription::IllegalParameter));

                // Handle failed reading from invalid packets
                return Poll::Ready(Err(err));
            }
        }
    }

    /// Attempts to decrypt the provied `message` if there is a decryptor set
    fn try_decrypt_message(&mut self, message: &mut Message) -> std::io::Result<()> {
        let decryptor = match &mut self.decryptor {
            Some(value) => value,
            None => return Ok(()),
        };

        if decryptor.decrypt(message) {
            return Ok(());
        }

        // Write the error alert message
        self.write_alert(AlertError::fatal(AlertDescription::BadRecordMac));

        Err(std::io::Error::new(ErrorKind::Other, "Bad record mac"))
    }

    /// Triggers a shutdown by sending a CloseNotify alert
    ///
    /// # Arguments
    /// * cx - The polling context
    fn poll_shutdown_priv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Send the alert if not already stopping
        if !self.stopped {
            // Send the shutdown close notify
            self.write_alert(AlertError::warning(AlertDescription::CloseNotify));
        }

        // Flush any data before shutdown
        self.poll_flush_priv(cx)
    }

    /// Fragments the provided message and encrypts the contents if
    /// encryption is available writing the output to the underlying
    /// stream
    ///
    /// # Arguments
    /// * message - The message to write
    pub(crate) fn write_message(&mut self, message: Message) {
        for mut msg in message.fragment() {
            if let Some(writer) = &mut self.encryptor {
                writer.encrypt(&mut msg)
            }

            msg.encode(&mut self.write_buffer);
        }
    }

    /// Writes an alert message and updates the stopped state
    ///
    /// # Arguments
    /// * alert - The alert to write
    pub(crate) fn write_alert(&mut self, alert: AlertError) {
        let mut payload = Vec::new();
        alert.encode(&mut payload);

        let message = Message::new(MessageType::Alert, payload);

        // Internally handle the alert being sent
        self.write_message(message);

        // Handle stopping from an alert
        self.stopped = true;
    }

    /// Writes the provided bytes as application data to the
    /// app write buffer
    fn write_app_data(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.stopped {
            return Err(io_closed());
        };
        self.app_write_buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Polls reading application data from the app
    fn poll_read_priv(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Poll flushing the write buffer before attempting to read
        ready!(self.poll_flush_priv(cx))?;

        if self.stopped {
            return Poll::Ready(Err(io_closed()));
        }

        // Poll for app data from the stream
        let count = ready!(self.poll_app_data(cx))?;

        // Handle already stopped streams
        if self.stopped {
            return Poll::Ready(Err(io_closed()));
        }

        // Calculate the amount to read based on the buf size and the amount stored
        let read = cmp::min(buf.remaining(), count);
        if read > 0 {
            // Provide the data and replace the stored slice
            let new_buffer = self.app_read_buffer.split_off(read);
            buf.put_slice(&self.app_read_buffer);
            self.app_read_buffer = new_buffer;
        }

        Poll::Ready(Ok(()))
    }

    /// Polls flushing all the data for this stream that includes app data
    /// and the write buffer. This involves writing everything to the write
    /// buffer and then writing all the data to the stream and attempting
    /// to flush the stream
    pub(crate) fn poll_flush_priv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Write any written app data as a message to the write buffer
        if !self.app_write_buffer.is_empty() {
            let message = Message::new(
                MessageType::ApplicationData,
                self.app_write_buffer.split_off(0),
            );

            self.write_message(message);
        }

        // Try flushing the internal write buffer
        let mut write_count: usize = 0;
        while !self.write_buffer.is_empty() {
            let stream = Pin::new(&mut self.stream);
            let count = ready!(stream.poll_write(cx, &self.write_buffer))?;
            if count > 0 {
                self.write_buffer = self.write_buffer.split_off(count);
                write_count += count;
            }
        }

        // Skip flushing if we haven't written any data
        if write_count == 0 {
            return Poll::Ready(Ok(()));
        }

        // Try flush the underlying stream
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    /// Polls for application data or returns the already present amount of application
    /// data stored in this stream, Collects application data by polling for messages
    fn poll_app_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let buffer_len = self.app_read_buffer.len();

        // Early return if the buffer is not yet empty
        if buffer_len != 0 {
            return Poll::Ready(Ok(buffer_len));
        }

        // Poll for the next message
        let message = ready!(self.poll_next_message(cx))?;

        match message.message_type {
            // Handle errors from the client
            MessageType::Alert => {
                let alert = AlertError::from_message(&message);

                // Stop the stream
                self.stopped = true;

                // On error ready 0 bytes
                Poll::Ready(Err(io::Error::new(ErrorKind::Other, alert)))
            }

            // Handle application data
            MessageType::ApplicationData => {
                let payload = message.payload;
                self.app_read_buffer.extend_from_slice(&payload);
                Poll::Ready(Ok(payload.len()))
            }

            // Unexpected message kind
            _ => {
                self.write_alert(AlertError::fatal(AlertDescription::UnexpectedMessage));

                Poll::Ready(Err(io::Error::new(
                    ErrorKind::Other,
                    "Expected application data but got something else",
                )))
            }
        }
    }
}

impl AsyncRead for BlazeStream {
    /// Read polling handled by internal poll_read_priv
    ///
    /// # Arguments
    /// * cx - The polling context
    /// * buf - The read buffer to read to
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_priv(cx, buf)
    }
}

impl AsyncWrite for BlazeStream {
    /// Writing polling is always ready as the data is written
    /// directly to a vec buffer
    ///
    /// # Arguments
    /// * _cx - The polling context
    /// * buf - The slice of bytes to write as app data
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(self.get_mut().write_app_data(buf))
    }

    /// Polls the internal flushing funciton
    ///
    /// # Arguments
    /// * cx - The polling context
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_flush_priv(cx)
    }

    /// Polls the internal shutdown function
    ///
    /// # Arguments
    /// * cx - The polling context
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_shutdown_priv(cx)
    }
}

/// Creates an error indicating that the stream is closed
fn io_closed() -> io::Error {
    io::Error::new(ErrorKind::UnexpectedEof, "Connection closed")
}
