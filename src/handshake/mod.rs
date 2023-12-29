use self::{client::ExpectServerHello, server::ExpectClientHello};
use crate::{
    data::BlazeServerData,
    msg::{
        handshake::{ClientHello, HandshakePayload},
        joiner::HandshakeJoiner,
        transcript::MessageTranscript,
        types::{AlertDescription, CipherSuite, MessageType, SSLRandom},
        AlertMessage, Message,
    },
    AlertError, BlazeStream,
};
use std::{
    future::Future,
    io::ErrorKind,
    sync::Arc,
    task::{ready, Poll},
};

pub(crate) mod client;
pub(crate) mod server;

/// Holder for handshaking related state
pub(crate) struct HandshakeState<'a> {
    /// Backing stream which is used for the handshaking process
    stream: &'a mut BlazeStream,
    /// Transcript for recording messages to compute the finish hashes
    transcript: MessageTranscript,
    /// Message joiner for joining
    joiner: HandshakeJoiner,
    /// Handler for handling the next messsage recieved, will be
    /// [None] if the handshaking process has finished or an error
    /// occured in the current handler
    handler: Option<Box<dyn MessageHandler>>,
}

/// Macro for expecting a specific handshake payload type returning
/// an unexpected message error for the incorrect handshake
#[macro_export]
macro_rules! expect_handshake {
    ( $message:ident, $name:ident) => {
        match $message {
            HandshakePayload::$name(value) => value,
            _ => return Err(AlertError::fatal(AlertDescription::UnexpectedMessage)),
        }
    };
}

impl Future for HandshakeState<'_> {
    type Output = std::io::Result<()>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let this = self.get_mut();

        while this.handler.is_some() {
            // Poll flushing the underlying stream before writing
            ready!(this.stream.poll_flush_priv(cx))?;

            // Poll the stream for the next message
            let message = ready!(this.stream.poll_next_message(cx))?;

            // Handle client alerts (This implementation treats all as fatal)
            if matches!(&message.message_type, MessageType::Alert) {
                let alert = AlertMessage::from_message(&message);
                this.stream.stopped = true;
                return Poll::Ready(Err(std::io::Error::new(
                    ErrorKind::Other,
                    AlertError {
                        level: alert.0,
                        description: alert.1,
                    },
                )));
            }

            // Handle the recieved message
            if let Err(err) = this.handle_message(message) {
                this.stream
                    .write_alert(AlertMessage(err.level, err.description));

                return Poll::Ready(Err(std::io::Error::new(ErrorKind::Other, err)));
            }
        }

        // No more handlers, connection is complete
        Poll::Ready(Ok(()))
    }
}

impl<'a> HandshakeState<'a> {
    /// Creates the state for a handshake from the server
    /// perspective
    pub fn create_server(
        stream: &'a mut BlazeStream,
        server_data: Arc<BlazeServerData>,
    ) -> HandshakeState<'a> {
        Self {
            stream,
            transcript: Default::default(),
            joiner: Default::default(),
            handler: Some(Box::new(ExpectClientHello { server_data })),
        }
    }

    /// Creates the state for a handshake from the client
    /// perspective
    pub fn create_client(stream: &'a mut BlazeStream) -> HandshakeState<'a> {
        let client_random: SSLRandom = SSLRandom::default();

        let mut state = Self {
            stream,
            transcript: Default::default(),
            joiner: Default::default(),
            handler: Some(Box::new(ExpectServerHello {
                client_random: client_random.clone(),
            })),
        };

        // Write the initial client hello message
        state.write_handshake(HandshakePayload::ClientHello(ClientHello {
            random: client_random,
            cipher_suites: vec![
                CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
                CipherSuite::TLS_RSA_WITH_RC4_128_MD5,
            ],
        }));

        state
    }

    /// Handles an incoming message and passing the message
    /// to the current handler
    pub fn handle_message(&mut self, message: Message) -> Result<(), AlertError> {
        let handler = match self.handler.take() {
            Some(value) => value,
            None => return Ok(()),
        };

        if let MessageType::Handshake = message.message_type {
            // Consume the message frame using the joiner
            self.joiner.consume(message);

            // Try and take a completed handshake message
            let handshake = match self.joiner.next() {
                Some(value) => value,
                None => return Ok(()),
            };

            // Don't include finished messages in the transcript
            if matches!(&handshake.handshake, HandshakePayload::Finished(_)) {
                // Peer has finished
                self.transcript.end_peer();
            }

            // Add the message bytes to the transcript
            self.transcript.push_raw(&handshake.payload);

            self.handler = handler.on_handshake(self, handshake.handshake)?;
        } else {
            self.handler = handler.on_message(self, message)?;
        }

        Ok(())
    }

    /// Handles writing a message to the underying stream
    #[inline]
    pub fn write_message(&mut self, message: Message) {
        // Write the message to the stream
        self.stream.write_message(message);
    }

    /// Handles writing a handshake message to the underlying
    /// stream, if the message is not the finish message its
    /// also written to the transcript
    pub fn write_handshake(&mut self, message: HandshakePayload) {
        let is_finished = matches!(message, HandshakePayload::Finished(_));
        let message: Message = message.into();

        if is_finished {
            // The peer transcript ends when a finished message is sent
            self.transcript.end_peer();
        }

        self.transcript.push_message(&message);

        // Write the message to the stream
        self.write_message(message);
    }
}

/// Result of a message handler, can either be the next handler
/// or an [AlertError] if an error occurred
type HandleResult = Result<Option<Box<dyn MessageHandler>>, AlertError>;

/// Handler for processing incoming messages for processing
/// handshaking state
#[allow(unused_variables)]
pub(crate) trait MessageHandler: Send + Sync + 'static {
    /// Handles an incoming message. Returns the next [MessageHandler] to use
    ///
    /// The default implemention expects the message to be a handshake
    /// and passes the message to [MessageHandler::on_handshake]
    fn on_message(self: Box<Self>, state: &mut HandshakeState, message: Message) -> HandleResult {
        Err(AlertError::fatal(AlertDescription::UnexpectedMessage))
    }

    /// Handles an incoming handshake message. Returns the next [MessageHandler] to use
    fn on_handshake(
        self: Box<Self>,
        state: &mut HandshakeState,
        message: HandshakePayload,
    ) -> HandleResult {
        Err(AlertError::fatal(AlertDescription::UnexpectedMessage))
    }
}
