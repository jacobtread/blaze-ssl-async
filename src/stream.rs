use crate::{
    crypto::MacGenerator,
    handshake::HandshakingWrapper,
    msg::{
        codec::{Codec, Reader},
        deframer::MessageDeframer,
        types::{AlertDescription, Certificate, MessageType},
        AlertMessage, Message,
    },
    rc4::{Rc4, Rc4Decryptor, Rc4Encryptor},
    try_ready, try_ready_into,
};
use lazy_static::lazy_static;
use rsa::RsaPrivateKey;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::{cmp, net::SocketAddr};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream, ToSocketAddrs},
};

lazy_static! {
    /// RSA private key used by the server
    pub static ref SERVER_KEY: RsaPrivateKey = {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::RsaPrivateKey;

        let key_pem = include_str!("key.pem");
        RsaPrivateKey::from_pkcs8_pem(key_pem)
            .expect("Failed to load redirector private key")
    };

    /// Certificate used by the server
    pub static ref SERVER_CERTIFICATE: Certificate = {
        let cert_pem = include_bytes!("cert.pem");
        let cert_bytes = pem_rfc7468::decode_vec(cert_pem)
            .expect("Unable to parse server certificate")
            .1;
        Certificate(cert_bytes)
    };
}

/// Wrapping structure for wrapping Read + Write streams with a SSLv3
/// protocol wrapping.
pub struct BlazeStream<S = TcpStream> {
    /// Underlying stream target
    stream: S,

    /// Message deframer for de-framing messages from the read stream
    deframer: MessageDeframer,

    /// Decryptor for decrypting messages if the stream is encrypted
    decryptor: Option<Rc4Decryptor>,
    /// Encryptor for encrypting messages if the stream should be encrypted
    encryptor: Option<Rc4Encryptor>,

    /// Buffer for input that is read from the application layer
    app_read_buffer: Vec<u8>,
    /// Buffer for output written to the application layer
    /// (Written to stream when connection is flushed)
    app_write_buffer: Vec<u8>,

    /// Buffer for the raw packet contents that are going to be
    /// written to the stream
    write_buffer: Vec<u8>,

    /// State determining whether the stream is stopped
    stopped: bool,
}

impl<S> BlazeStream<S> {
    /// Returns a mutable reference ot
    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[derive(Debug)]
pub enum BlazeError {
    /// IO
    IO(io::Error),
    /// Fatal alert occurred
    FatalAlert(AlertDescription),
    /// The stream is stopped
    Stopped,
}

impl From<io::Error> for BlazeError {
    fn from(err: io::Error) -> Self {
        BlazeError::IO(err)
    }
}

pub type BlazeResult<T> = Result<T, BlazeError>;

/// Mode to use when starting the handshake. Server mode will
/// handshake as the server entity and client will handshake
/// as a client entity
pub enum StreamMode {
    /// Stream is a stream created by a server listener
    Server,
    /// Stream is a client stream connecting to a server
    Client,
}

impl StreamMode {
    /// Inverts the provided stream mode returning the opposite mode
    pub fn invert(&self) -> StreamMode {
        match self {
            Self::Server => Self::Client,
            Self::Client => Self::Server,
        }
    }
}

impl BlazeStream<TcpStream> {
    /// Connects to a remote address creating a client blaze stream
    /// to that address.
    ///
    /// `addr` The address to connect to
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> BlazeResult<Self> {
        let stream = TcpStream::connect(addr).await?;
        Self::new(stream, StreamMode::Client).await
    }
}

impl<S> BlazeStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new blaze stream wrapping the provided value with
    /// the provided stream mode
    ///
    /// `value` The value to wrap
    /// `mode`  The stream mode
    pub async fn new(value: S, mode: StreamMode) -> BlazeResult<Self> {
        // Wrap the stream in a blaze stream
        let stream = Self {
            stream: value,
            deframer: MessageDeframer::new(),
            decryptor: None,
            encryptor: None,
            app_write_buffer: Vec::new(),
            app_read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            stopped: false,
        };

        // Wrap the blaze stream and complete the handshake
        let mut wrapper = HandshakingWrapper::new(stream, mode);
        let result = wrapper.handshake().await;
        let mut stream = wrapper.into_inner();
        if let Err(err) = result {
            // Try flushing any remaining messages (Errors) and ignore errors
            stream.flush().await.ok();
            return Err(err);
        }

        // Return the unwrapped stream
        Ok(stream)
    }

    /// Creates a new RC4 encryptor from the provided key and mac
    /// generator assigning the stream encryptor to it
    ///
    /// `key` The key to use
    /// `mac` The mac generator to use
    pub fn set_encryptor(&mut self, key: Rc4, mac: MacGenerator) {
        self.encryptor = Some(Rc4Encryptor::new(key, mac))
    }

    /// Creates a new RC4 decryptor from the provided key and mac
    /// generator assigning the stream decryptor to it
    ///
    /// `key` The key to use
    /// `mac` The mac generator to use
    pub fn set_decryptor(&mut self, key: Rc4, mac: MacGenerator) {
        self.decryptor = Some(Rc4Decryptor::new(key, mac))
    }

    /// Polls for the next message to be recieved. Decryptes encrypted messages
    /// and handles alert messages.
    ///
    /// `cx` The polling context
    pub fn poll_next_message(&mut self, cx: &mut Context<'_>) -> Poll<BlazeResult<Message>> {
        loop {
            // Stopped streams immeditely results in an error
            if self.stopped {
                return Poll::Ready(Err(BlazeError::Stopped));
            }

            // Try and take a message from the deframer
            if let Some(mut message) = self.deframer.next() {
                // Decrypt message if encryption is enabled
                if let Some(decryptor) = &mut self.decryptor {
                    if !decryptor.decrypt(&mut message) {
                        return Poll::Ready(Err(self.alert_fatal(AlertDescription::BadRecordMac)));
                    }
                }

                return Poll::Ready(if message.message_type == MessageType::Alert {
                    // Handle alert messages
                    Err(self.handle_alert_message(message))
                } else {
                    Ok(message)
                });
            }

            let stream = Pin::new(&mut self.stream);
            if !try_ready_into!(self.deframer.poll_read(cx, stream)) {
                return Poll::Ready(Err(self.alert_fatal(AlertDescription::IllegalParameter)));
            }
        }
    }

    /// Handles recieved alert messages first parsing the message and then
    /// handling it based on its type and returning the respective error
    /// for the type.
    ///
    /// `message` The raw alert message
    fn handle_alert_message(&mut self, message: Message) -> BlazeError {
        // Attempt to read the message
        let mut reader = Reader::new(&message.payload);
        let description = AlertMessage::decode(&mut reader)
            .map(|value| value.1)
            .unwrap_or_else(|| AlertDescription::Unknown(0));

        // All alerts result in shutdown
        self.stopped = true;

        // Handle close notify messages as non errors
        if matches!(description, AlertDescription::CloseNotify) {
            BlazeError::Stopped
        } else {
            // All error alerts are consider to be fatal in this implementation
            BlazeError::FatalAlert(description)
        }
    }

    /// Sets the stopped state to true and sends the close
    /// notify alert if shutdown has not already been called
    fn shutdown(&mut self) {
        if !self.stopped {
            self.alert(&AlertDescription::CloseNotify);
            self.stopped = true;
        }
    }

    /// Triggers a shutdown by sending a CloseNotify alert
    fn poll_shutdown_priv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown();
        // Flush any data before shutdown
        self.poll_flush_priv(cx)
    }

    /// Fragments the provided message and encrypts the contents if
    /// encryption is available writing the output to the underlying
    /// stream
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

    /// Writes an alert message and calls `handle_alert` with the alert
    pub(crate) fn alert(&mut self, alert: &AlertDescription) {
        let message = Message {
            message_type: MessageType::Alert,
            payload: alert.encode_vec(),
        };
        // Internally handle the alert being sent
        self.write_message(message);
    }

    /// Handles a fatal alert where an unexpected message was recieved
    /// returning the error created
    pub(crate) fn fatal_unexpected(&mut self) -> BlazeError {
        self.alert_fatal(AlertDescription::UnexpectedMessage)
    }

    /// Handles a fatal alert where an illegal parameter was recieved
    /// returning the error created
    pub(crate) fn fatal_illegal(&mut self) -> BlazeError {
        self.alert_fatal(AlertDescription::IllegalParameter)
    }

    /// Writes a fatal alert and calls shutdown returning a
    /// BlazeError for the alert
    fn alert_fatal(&mut self, alert: AlertDescription) -> BlazeError {
        self.alert(&alert);
        // Shutdown the stream because of fatal error
        self.shutdown();
        BlazeError::FatalAlert(alert)
    }

    /// Writes the provided bytes as application data to the
    /// app write buffer
    ///
    /// `buf` The buffer to write
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
        // Poll flushing the
        try_ready!(self.poll_flush_priv(cx));

        // Poll for app data from the stream
        let count = try_ready!(self.poll_app_data(cx));

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
    fn poll_flush_priv(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if self.stopped {
            return Poll::Ready(Err(io_closed()));
        }

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
            let count = try_ready!(stream.poll_write(cx, &self.write_buffer));
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
        if self.stopped {
            return Poll::Ready(Err(io_closed()));
        }
        let buffer_len = self.app_read_buffer.len();
        let count = if buffer_len == 0 {
            let message = match ready!(self.poll_next_message(cx)) {
                Ok(value) => value,
                Err(_) => {
                    return Poll::Ready(Err(io::Error::new(
                        ErrorKind::ConnectionAborted,
                        "Ssl Failure",
                    )))
                }
            };

            // The alert message type is already handled in message polling so recieving
            // any messages that aren't application data here should be an error
            if message.message_type != MessageType::ApplicationData {
                // Alert unexpected message
                self.alert_fatal(AlertDescription::UnexpectedMessage);
                return Poll::Ready(Err(io::Error::new(
                    ErrorKind::Other,
                    "Expected application data but got something else",
                )));
            }

            let payload = message.payload;
            self.app_read_buffer.extend_from_slice(&payload);
            payload.len()
        } else {
            buffer_len
        };
        Poll::Ready(Ok(count))
    }
}

impl<S> AsyncRead for BlazeStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Read polling handled by internal poll_read_priv
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.get_mut().poll_read_priv(cx, buf)
    }
}

impl<S> AsyncWrite for BlazeStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Writing polling is always ready as the data is written
    /// directly to a vec buffer
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(self.get_mut().write_app_data(buf))
    }

    /// Polls the internal flushing funciton
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().poll_flush_priv(cx)
    }

    /// Polls the internal shutdown function
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().poll_shutdown_priv(cx)
    }
}

/// Implementation wrapping the tokio net TcpListener type
/// to automatically wrap accepted connections with a blaze
/// stream.
pub struct BlazeListener {
    /// The underlying TcpListener
    listener: TcpListener,
}

impl BlazeListener {
    /// Binds a new TcpListener wrapping it in a BlazeListener if no
    /// errors occurred
    ///
    /// `addr` The addr(s) to bind on
    pub async fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<BlazeListener> {
        let listener = TcpListener::bind(addr).await?;
        Ok(BlazeListener { listener })
    }

    /// Accepts a new TcpStream from the underlying listener wrapping
    /// it in a server BlazeStream returning the wrapped stream and the
    /// stream addr.
    ///
    /// Awaiting the blaze stream creation here would mean connections
    /// wouldnt be able to be accepted so instead a BlazeAccept is returned
    /// and `finish_accept` should be called within a spawned task otherwise
    /// you can use `blocking_accept` to do an immediate handle
    pub async fn accept(&self) -> io::Result<BlazeAccept> {
        let (stream, addr) = self.listener.accept().await?;
        Ok(BlazeAccept { stream, addr })
    }

    /// Alternative to accpet where the handshaking process is done straight away
    /// rather than in the BlazeAccept which will prevent new connections from
    /// being accepted until the current handshake is complete
    pub async fn blocking_accept(&self) -> BlazeResult<(BlazeStream<TcpStream>, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        let stream = BlazeStream::new(stream, StreamMode::Server).await?;
        Ok((stream, addr))
    }
}

/// Structure representing a stream accepted from
/// the underlying listener that is yet to be
/// converted into a BlazeStream
pub struct BlazeAccept {
    stream: TcpStream,
    addr: SocketAddr,
}

impl BlazeAccept {
    /// Finishes the accepting process for this connection. This should be called
    /// in a seperately spawned task to prevent blocking accepting new connections.
    /// Returns the wrapped blaze stream and the socket address
    pub async fn finish_accept(self) -> BlazeResult<(BlazeStream<TcpStream>, SocketAddr)> {
        let stream = BlazeStream::new(self.stream, StreamMode::Server).await?;
        Ok((stream, self.addr))
    }
}

/// Creates an error indicating that the stream is closed
fn io_closed() -> io::Error {
    io::Error::new(ErrorKind::Other, "Stream already closed")
}
