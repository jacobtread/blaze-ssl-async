use crate::crypto::HashAlgorithm;
use crate::handshake::HandshakingWrapper;
use crate::msg::{
    AlertDescription, AlertMessage, BorrowedMessage, Certificate, Codec, Message, MessageDeframer,
    MessageType, OpaqueMessage, Reader,
};
use crate::{try_ready, try_ready_into};
use crypto::rc4::Rc4;
use crypto::symmetriccipher::SynchronousStreamCipher;
use lazy_static::lazy_static;
use rsa::RsaPrivateKey;
use std::cmp;
use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
        use pem;
        let cert_pem = include_str!("cert.pem");
        let cert_bytes = pem::parse(cert_pem)
            .expect("Unable to parse server certificate")
            .contents;
        Certificate(cert_bytes)
    };
}

/// Wrapping structure for wrapping Read + Write streams with a SSLv3
/// protocol wrapping.
pub struct BlazeStream<S> {
    /// Underlying stream target
    pub(crate) stream: S,

    /// Message deframer for de-framing messages from the read stream
    deframer: MessageDeframer,

    /// Processor for pre-processing messages that have been read
    pub(crate) read_processor: ReadProcessor,
    /// Process for pre-processing messages that are being sent
    pub(crate) write_processor: WriteProcessor,

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
    /// Get a reference to the underlying stream
    pub fn get_ref(&self) -> &S {
        return &self.stream;
    }

    /// Get a mutable reference to the underlying stream
    pub fn get_mut(&mut self) -> &mut S {
        return &mut self.stream;
    }
}

#[derive(Debug)]
pub enum BlazeError {
    IO(io::Error),
    FatalAlert(AlertDescription),
    Stopped,
    Unsupported,
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
#[derive(Debug)]
pub enum StreamMode {
    Server,
    Client,
}

impl<S> AsyncRead for BlazeStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.get_mut().poll_read_impl(cx, buf)
    }
}

impl<S> AsyncWrite for BlazeStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Poll::Ready(self.get_mut().write(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().poll_flush_impl(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Poll::Ready(Ok(()))
    }
}

impl<S> BlazeStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn new(value: S, mode: StreamMode) -> BlazeResult<Self> {
        let stream = Self {
            stream: value,
            deframer: MessageDeframer::new(),
            read_processor: ReadProcessor::None,
            write_processor: WriteProcessor::None,
            app_write_buffer: Vec::new(),
            app_read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            stopped: false,
        };
        let wrapper = HandshakingWrapper::new(stream, mode);
        wrapper.handshake().await
    }

    pub fn poll_next_message(&mut self, cx: &mut Context<'_>) -> Poll<BlazeResult<Message>> {
        loop {
            // Stopped streams immeditely results in an error
            if self.stopped {
                return Poll::Ready(Err(BlazeError::Stopped));
            }

            if let Some(message) = self.deframer.next() {
                let message = match self.read_processor.process(message) {
                    Ok(value) => value,
                    Err(err) => {
                        return Poll::Ready(Err(match err {
                            DecryptError::InvalidMac => {
                                self.alert_fatal(AlertDescription::BadRecordMac)
                            }
                        }))
                    }
                };

                if message.message_type == MessageType::Alert {
                    let mut reader = Reader::new(&message.payload);
                    if let Some(message) = AlertMessage::decode(&mut reader) {
                        self.handle_alert(message.1)?;
                        continue;
                    } else {
                        return Poll::Ready(Err(self.handle_fatal(AlertDescription::Unknown(0))));
                    }
                }

                return Poll::Ready(Ok(message));
            }

            let stream = Pin::new(&mut self.stream);

            if !try_ready_into!(self.deframer.poll_read(cx, stream)) {
                return Poll::Ready(Err(self.alert_fatal(AlertDescription::IllegalParameter)));
            }
        }
    }

    /// Triggers a shutdown by sending a CloseNotify alert
    pub fn shutdown(&mut self) -> BlazeResult<()> {
        self.alert(AlertDescription::CloseNotify)
    }

    /// Handle the alert message provided
    pub fn handle_alert(&mut self, alert: AlertDescription) -> BlazeResult<()> {
        match alert {
            AlertDescription::CloseNotify => {
                // We are closing flush and set stopped
                // let _ = self.flush().await;
                self.stopped = true;
                Ok(())
            }
            _ => Err(BlazeError::FatalAlert(alert)),
        }
    }

    /// Handle a fatal alert (Stop the connection and don't attempt more reads/writes)
    pub fn handle_fatal(&mut self, alert: AlertDescription) -> BlazeError {
        self.stopped = true;
        return BlazeError::FatalAlert(alert);
    }

    /// Fragments the provided message and encrypts the contents if
    /// encryption is available writing the output to the underlying
    /// stream
    pub fn write_message(&mut self, message: Message) {
        for msg in message.fragment() {
            let msg = self.write_processor.process(msg);
            let bytes = msg.encode();
            self.write_buffer.extend_from_slice(&bytes);
        }
    }

    /// Writes an alert message and calls `handle_alert` with the alert
    pub fn alert(&mut self, alert: AlertDescription) -> BlazeResult<()> {
        let message = Message {
            message_type: MessageType::Alert,
            payload: alert.encode_vec(),
        };
        // Internally handle the alert being sent
        self.handle_alert(alert)?;
        self.write_message(message);
        Ok(())
    }

    pub fn fatal_unexpected(&mut self) -> BlazeError {
        self.alert_fatal(AlertDescription::UnexpectedMessage)
    }

    pub fn fatal_illegal(&mut self) -> BlazeError {
        self.alert_fatal(AlertDescription::IllegalParameter)
    }

    pub fn alert_fatal(&mut self, alert: AlertDescription) -> BlazeError {
        let message = Message {
            message_type: MessageType::Alert,
            payload: alert.encode_vec(),
        };
        let _ = self.write_message(message);
        // Internally handle the alert being sent
        self.handle_fatal(alert)
    }

    pub fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.stopped {
            return Err(io_closed());
        };
        self.app_write_buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn poll_flush_impl(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        if self.stopped {
            return Poll::Ready(Err(io_closed()));
        }
        if !self.app_write_buffer.is_empty() {
            let message = Message {
                message_type: MessageType::ApplicationData,
                payload: self.app_write_buffer.split_off(0),
            };
            self.write_message(message);
        }

        while !self.write_buffer.is_empty() {
            let stream = Pin::new(&mut self.stream);
            let count = match ready!(stream.poll_write(cx, &self.write_buffer)) {
                Ok(count) => count,
                Err(err) => return Poll::Ready(Err(err)),
            };
            if count > 0 {
                self.write_buffer = self.write_buffer.split_off(count);
            }
        }
        let stream = Pin::new(&mut self.stream);
        stream.poll_flush(cx)
    }

    pub fn poll_fill_app_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
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
            if message.message_type != MessageType::ApplicationData {
                // Alert unexpected message
                self.alert_fatal(AlertDescription::UnexpectedMessage);
                return Poll::Ready(Ok(0));
            }

            let payload = message.payload;
            self.app_read_buffer.extend_from_slice(&payload);
            payload.len()
        } else {
            buffer_len
        };
        Poll::Ready(Ok(count))
    }

    pub fn poll_read_impl(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let count = try_ready!(self.poll_fill_app_data(cx));

        if self.stopped {
            return Poll::Ready(Err(io_closed()));
        }

        let read = cmp::min(buf.remaining(), count);
        if read > 0 {
            let new_buffer = self.app_read_buffer.split_off(read);
            buf.put_slice(&self.app_read_buffer);
            self.app_read_buffer = new_buffer;
        }

        Poll::Ready(Ok(()))
    }
}

/// Creates an error indicating that the stream is closed
fn io_closed() -> io::Error {
    io::Error::new(ErrorKind::Other, "Stream already closed")
}

/// Handler for processing messages that need to be written
/// converts them to writing messages
pub enum WriteProcessor {
    /// NO-OP Write processor which directly converts the message to OpaqueMessage
    None,
    /// RC4 Encryption processor which encrypts the message before converting
    RC4 {
        alg: HashAlgorithm,
        key: Rc4,
        mac_secret: Vec<u8>,
        seq: u64,
    },
}

impl WriteProcessor {
    /// Processes the provided message using the underlying method and creates an
    /// Opaque message that can be written from it.
    ///
    /// `message` The message to process for writing
    /// `seq` The current sequence number for this message
    pub fn process(&mut self, message: BorrowedMessage) -> OpaqueMessage {
        match self {
            // NO-OP directly convert message into output
            WriteProcessor::None => OpaqueMessage {
                message_type: message.message_type,
                payload: message.payload.to_vec(),
            },
            // RC4 Encryption
            WriteProcessor::RC4 {
                alg,
                key,
                mac_secret,
                seq,
            } => {
                let mut payload = message.payload.to_vec();

                alg.append_mac(&mut payload, mac_secret, message.message_type.value(), seq);

                let mut payload_enc = vec![0u8; payload.len()];
                key.process(&payload, &mut payload_enc);

                *seq += 1;

                OpaqueMessage {
                    message_type: message.message_type,
                    payload: payload_enc,
                }
            }
        }
    }
}

/// Handler for processing messages that have been read
/// and turning them into their actual messages
pub enum ReadProcessor {
    /// NO-OP Write processor which directly converts the message to Message
    None,
    /// RC4 Decryption processor which decrypts the message before converting
    RC4 {
        alg: HashAlgorithm,
        key: Rc4,
        mac_secret: Vec<u8>,
        seq: u64,
    },
}

#[derive(Debug)]
pub enum DecryptError {
    /// The mac address of the decrypted payload didn't match the
    /// computed value
    InvalidMac,
}

type DecryptResult<T> = Result<T, DecryptError>;

impl ReadProcessor {
    pub fn process(&mut self, message: OpaqueMessage) -> DecryptResult<Message> {
        Ok(match self {
            // NO-OP directly convert message into output
            ReadProcessor::None => Message {
                message_type: message.message_type,
                payload: message.payload,
            },
            // RC4 Decryption
            ReadProcessor::RC4 {
                alg,
                key,
                mac_secret,
                seq,
            } => {
                let mut payload_and_mac = vec![0u8; message.payload.len()];
                key.process(&message.payload, &mut payload_and_mac);

                let mac_start = payload_and_mac.len() - alg.hash_length();
                let payload = &payload_and_mac[..mac_start];
                let mac = &payload_and_mac[mac_start..];

                {
                    let valid_mac = alg.compare_mac(
                        mac,
                        mac_secret,
                        message.message_type.value(),
                        &payload,
                        seq,
                    );
                    if !valid_mac {
                        return Err(DecryptError::InvalidMac);
                    }
                }

                *seq += 1;

                Message {
                    message_type: message.message_type,
                    payload: payload.to_vec(),
                }
            }
        })
    }
}
