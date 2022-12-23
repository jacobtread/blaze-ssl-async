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
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

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
    stream: S,

    /// Message deframer for de-framing messages from the read stream
    deframer: MessageDeframer,

    /// Processor for pre-processing messages that have been read
    pub(crate) read_processor: Option<RC4Reader>,
    /// Process for pre-processing messages that are being sent
    pub(crate) write_processor: Option<RC4Writer>,

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
        self.get_mut().poll_read_priv(cx, buf)
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
        Poll::Ready(self.get_mut().write_app_data(buf))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().poll_flush_priv(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        self.get_mut().poll_shutdown_priv(cx)
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
            read_processor: None,
            write_processor: None,
            app_write_buffer: Vec::new(),
            app_read_buffer: Vec::new(),
            write_buffer: Vec::new(),
            stopped: false,
        };
        let mut wrapper = HandshakingWrapper::new(stream, mode);
        let result = wrapper.handshake().await;
        let mut stream = wrapper.into_inner();
        if let Err(err) = result {
            // Try flushing any remaining messages (Errors) and ignore errors
            stream.flush().await.ok();
            return Err(err);
        }

        Ok(stream)
    }

    pub fn poll_next_message(&mut self, cx: &mut Context<'_>) -> Poll<BlazeResult<Message>> {
        loop {
            // Stopped streams immeditely results in an error
            if self.stopped {
                return Poll::Ready(Err(BlazeError::Stopped));
            }

            if let Some(message) = self.deframer.next() {
                let message = match &mut self.read_processor {
                    Some(reader) => match reader.process(message) {
                        Ok(value) => value,
                        Err(_) => {
                            return Poll::Ready(Err(
                                self.alert_fatal(AlertDescription::BadRecordMac)
                            ))
                        }
                    },
                    None => Message {
                        message_type: message.message_type,
                        payload: message.payload,
                    },
                };

                if message.message_type == MessageType::Alert {
                    let mut reader = Reader::new(&message.payload);
                    if let Some(message) = AlertMessage::decode(&mut reader) {
                        if matches!(message.1, AlertDescription::CloseNotify) {
                            self.alert(message.1);
                            self.shutdown_impl();
                            return Poll::Ready(Err(BlazeError::Stopped));
                        } else {
                            self.alert(message.1.clone());
                            return Poll::Ready(Err(BlazeError::FatalAlert(message.1)));
                        }
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

    pub fn shutdown_impl(&mut self) {
        if !self.stopped {
            self.alert(AlertDescription::CloseNotify);
            self.stopped = true;
        }
    }

    /// Triggers a shutdown by sending a CloseNotify alert
    pub fn poll_shutdown_priv(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown_impl();
        // Flush any data before shutdown
        self.poll_flush_priv(cx)
    }

    /// Handle a fatal alert (Stop the connection and don't attempt more reads/writes)
    pub fn handle_fatal(&mut self, alert: AlertDescription) -> BlazeError {
        self.stopped = true;
        BlazeError::FatalAlert(alert)
    }

    /// Fragments the provided message and encrypts the contents if
    /// encryption is available writing the output to the underlying
    /// stream
    pub fn write_message(&mut self, message: Message) {
        for msg in message.fragment() {
            let msg = if let Some(writer) = &mut self.write_processor {
                writer.process(msg)
            } else {
                OpaqueMessage {
                    message_type: msg.message_type,
                    payload: msg.payload.to_vec(),
                }
            };
            let bytes = msg.encode();
            self.write_buffer.extend_from_slice(&bytes);
        }
    }

    /// Writes an alert message and calls `handle_alert` with the alert
    pub fn alert(&mut self, alert: AlertDescription) {
        let message = Message {
            message_type: MessageType::Alert,
            payload: alert.encode_vec(),
        };
        // Internally handle the alert being sent
        self.write_message(message);
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
        self.write_message(message);
        // Internally handle the alert being sent
        self.handle_fatal(alert)
    }

    /// Writes the provided bytes as application data to the
    /// app write buffer
    ///
    /// `buf` The buffer to write
    pub fn write_app_data(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.stopped {
            return Err(io_closed());
        };
        self.app_write_buffer.extend_from_slice(buf);
        Ok(buf.len())
    }

    /// Polls reading application data from the app
    pub fn poll_read_priv(
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
    pub fn poll_app_data(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
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

/// Creates an error indicating that the stream is closed
fn io_closed() -> io::Error {
    io::Error::new(ErrorKind::Other, "Stream already closed")
}

/// RC4 Encryption processor which encrypts the message before converting
pub struct RC4Writer {
    pub alg: HashAlgorithm,
    pub key: Rc4,
    pub mac_secret: Vec<u8>,
    pub seq: u64,
}

impl RC4Writer {
    pub fn process(&mut self, message: BorrowedMessage) -> OpaqueMessage {
        let mut payload = message.payload.to_vec();
        self.alg.append_mac(
            &mut payload,
            &self.mac_secret,
            message.message_type.value(),
            &self.seq,
        );
        let mut payload_enc = vec![0u8; payload.len()];
        self.key.process(&payload, &mut payload_enc);
        self.seq += 1;
        OpaqueMessage {
            message_type: message.message_type,
            payload: payload_enc,
        }
    }
}

/// RC4 Decryption processor which decrypts the message before converting
pub struct RC4Reader {
    pub alg: HashAlgorithm,
    pub key: Rc4,
    pub mac_secret: Vec<u8>,
    pub seq: u64,
}

impl RC4Reader {
    pub fn process(&mut self, message: OpaqueMessage) -> DecryptResult<Message> {
        let mut payload_and_mac = vec![0u8; message.payload.len()];
        self.key.process(&message.payload, &mut payload_and_mac);

        let mac_start = payload_and_mac.len() - self.alg.hash_length();
        let payload = &payload_and_mac[..mac_start];
        let mac = &payload_and_mac[mac_start..];

        {
            let valid_mac = self.alg.compare_mac(
                mac,
                &self.mac_secret,
                message.message_type.value(),
                payload,
                &self.seq,
            );
            if !valid_mac {
                return Err(DecryptError::InvalidMac);
            }
        }

        self.seq += 1;

        Ok(Message {
            message_type: message.message_type,
            payload: payload.to_vec(),
        })
    }
}

#[derive(Debug)]
pub enum DecryptError {
    /// The mac address of the decrypted payload didn't match the
    /// computed value
    InvalidMac,
}

type DecryptResult<T> = Result<T, DecryptError>;
