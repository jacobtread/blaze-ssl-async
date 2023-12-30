use super::{
    crypto::rc4::*,
    data::BlazeServerData,
    msg::{codec::*, deframer::MessageDeframer, types::*, AlertMessage, Message},
};
use crate::handshake::HandshakeState;
use std::{
    cmp,
    fmt::Display,
    io::{self, ErrorKind},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, ToSocketAddrs},
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
        if let Err(err) = HandshakeState::create_client(&mut stream).await {
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
    /// * `data` - The server data to use
    pub async fn accept(stream: TcpStream, data: Arc<BlazeServerData>) -> std::io::Result<Self> {
        let mut stream = Self::new(stream);

        // Complete the server handshake
        if let Err(err) = HandshakeState::create_server(&mut stream, data).await {
            // Ensure the stream is correctly flushed and shutdown on error
            _ = stream.shutdown().await;
            return Err(err);
        }

        Ok(stream)
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
                self.write_alert(AlertMessage(
                    AlertLevel::Fatal,
                    AlertDescription::IllegalParameter,
                ));

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
        self.write_alert(AlertMessage(
            AlertLevel::Fatal,
            AlertDescription::BadRecordMac,
        ));

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
            self.write_alert(AlertMessage(
                AlertLevel::Warning,
                AlertDescription::CloseNotify,
            ));
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
        for msg in message.fragment() {
            let msg = if let Some(writer) = &mut self.encryptor {
                writer.encrypt(msg)
            } else {
                Message {
                    message_type: msg.message_type,
                    payload: msg.payload.to_vec(),
                }
            };
            let bytes = msg.encode();
            self.write_buffer.extend_from_slice(&bytes);
        }
    }

    /// Writes an alert message and updates the stopped state
    ///
    /// # Arguments
    /// * alert - The alert to write
    pub(crate) fn write_alert(&mut self, alert: AlertMessage) {
        let mut payload = Vec::new();
        alert.encode(&mut payload);

        let message = Message {
            message_type: MessageType::Alert,
            payload,
        };
        // Internally handle the alert being sent
        self.write_message(message);

        // Handle stopping from an alert
        self.stopped = true;
    }

    /// Writes the provided bytes as application data to the
    /// app write buffer
    ///
    /// # Arguments
    /// * buf - The buffer to write
    fn write_app_data(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.stopped {
            return Err(io_closed());
        };
        self.app_write_buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Polls reading application data from the app
    ///
    /// # Arguments
    /// * cx -  The polling context
    /// * buf - The buffer to read data into
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
    ///
    /// # Arguments
    /// * cx - The polling context
    pub(crate) fn poll_flush_priv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Write any written app data as a message to the write buffer
        if !self.app_write_buffer.is_empty() {
            let message = Message {
                message_type: MessageType::ApplicationData,
                payload: self.app_write_buffer.split_off(0),
            };
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
    ///
    /// # Arguments
    /// * cx - The polling context
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
                let alert = AlertMessage::from_message(&message);

                // Stop the stream
                self.stopped = true;

                // On error ready 0 bytes
                Poll::Ready(Err(io::Error::new(
                    ErrorKind::Other,
                    AlertError {
                        level: alert.0,
                        description: alert.1,
                    },
                )))
            }

            // Handle application data
            MessageType::ApplicationData => {
                let payload = message.payload;
                self.app_read_buffer.extend_from_slice(&payload);
                Poll::Ready(Ok(payload.len()))
            }

            // Unexpected message kind
            _ => {
                self.write_alert(AlertMessage(
                    AlertLevel::Fatal,
                    AlertDescription::UnexpectedMessage,
                ));

                Poll::Ready(Err(io::Error::new(
                    ErrorKind::Other,
                    "Expected application data but got something else",
                )))
            }
        }
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

/// Listener wrapping TcpListener in order to accept
/// SSL connections
pub struct BlazeListener {
    /// The underlying TcpListener
    listener: TcpListener,
    /// The server data to use for initializing streams
    data: Arc<BlazeServerData>,
}

impl BlazeListener {
    /// Replaces the server private key and certificate used
    /// for accepting connections
    ///
    /// ## Arguments
    /// * `data` - The new server data
    pub fn set_server_data(&mut self, data: Arc<BlazeServerData>) {
        self.data = data;
    }

    /// Obtains the local address that the underlying listener is
    /// bound to
    #[inline]
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Binds a new TcpListener wrapping it in a BlazeListener if no
    /// errors occurred
    ///
    /// ## Arguments
    /// * `addr` - The addr(s) to attempt to bind on
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<BlazeListener> {
        let listener = TcpListener::bind(addr).await?;
        Ok(BlazeListener {
            listener,
            data: Arc::default(),
        })
    }

    /// Polls accepting a connection from the underlying listener.
    ///
    /// This function does *not* complete the SSL handshake, instead it
    /// gives you a [BlazeAccept] and you can use [BlazeAccept::finish_accept]
    /// to complete the handshake
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<BlazeAccept>> {
        let (stream, addr) = ready!(self.listener.poll_accept(cx))?;
        Poll::Ready(Ok(BlazeAccept {
            stream,
            addr,
            data: self.data.clone(),
        }))
    }

    /// Accepts a new TcpStream from the underlying listener wrapping
    /// it in a server BlazeStream returning the wrapped stream and the
    /// stream addr.
    ///
    /// Awaiting the blaze stream creation here would mean connections
    /// wouldnt be able to be accepted so instead a BlazeAccept is returned
    /// and `finish_accept` should be called within a spawned task otherwise
    /// you can use `blocking_accept` to do an immediate handle
    pub async fn accept(&self) -> std::io::Result<BlazeAccept> {
        let (stream, addr) = self.listener.accept().await?;
        Ok(BlazeAccept {
            stream,
            addr,
            data: self.data.clone(),
        })
    }

    /// Alternative to accpet where the handshaking process is done straight away
    /// rather than in the BlazeAccept, this will prevent new connections from
    /// being accepted until the current handshake is complete
    pub async fn blocking_accept(&self) -> std::io::Result<(BlazeStream, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        let stream = BlazeStream::accept(stream, self.data.clone()).await?;

        Ok((stream, addr))
    }
}

/// Structure representing a stream accepted from
/// the underlying listener that is yet to be
/// converted into a BlazeStream
///
/// Represents an stream accepting from a [BlazeListener] that
/// has not yet completed its SSL handshake.
///
/// To complete the handshake and get a [BlazeStream] call the
/// [BlazeAccept::finish_accept] function
pub struct BlazeAccept {
    /// The underlying stream
    stream: TcpStream,
    /// The socket address to the stream
    addr: SocketAddr,
    /// The server data to use for initializing the stream
    data: Arc<BlazeServerData>,
}

impl BlazeAccept {
    /// Completes the SSL handshake for this accepting connection turning it
    /// into a [BlazeStream] so that it can be used
    pub async fn finish_accept(self) -> std::io::Result<(BlazeStream, SocketAddr)> {
        BlazeStream::accept(self.stream, self.data)
            .await
            .map(|stream| (stream, self.addr))
    }
}

/// Creates an error indicating that the stream is closed
pub(crate) fn io_closed() -> io::Error {
    io::Error::new(ErrorKind::UnexpectedEof, "Connection closed")
}

/// Error caused by an alert
#[derive(Debug)]
pub(crate) struct AlertError {
    /// The level of the alert
    pub level: AlertLevel,
    /// The alert description
    pub description: AlertDescription,
}

impl AlertError {
    pub fn fatal(description: AlertDescription) -> Self {
        Self {
            level: AlertLevel::Fatal,
            description,
        }
    }
}

impl Display for AlertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{} alert: {}", self.level, self.description))
    }
}

impl std::error::Error for AlertError {}
