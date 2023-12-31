//! Module contains logic and state for completing the
//! SSL handshaking process

use crate::{
    listener::BlazeServerContext,
    msg::{
        handshake::{ClientHello, HandshakeMessage},
        joiner::HandshakeJoiner,
        transcript::MessageTranscript,
        types::{AlertDescription, CipherSuite, HandshakeType, MessageType, SSLRandom},
        AlertError, Message,
    },
    stream::BlazeStream,
};
use std::{
    future::Future,
    io::ErrorKind,
    sync::Arc,
    task::{ready, Poll},
};

mod client;
mod server;

/// Holder for handshaking related state
pub(crate) struct Handshaking<'a> {
    /// Backing stream which is used for the handshaking process
    pub stream: &'a mut BlazeStream,
    /// Transcript for recording messages to compute the finish hashes
    transcript: MessageTranscript,
    /// Message joiner for joining
    joiner: HandshakeJoiner,
    /// Handler for handling the next messsage recieved, will be
    /// [None] if the handshaking process has finished or an error
    /// occured in the current handler
    handler: Option<Box<dyn MessageHandler>>,
}

impl Future for Handshaking<'_> {
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
                let alert = AlertError::from_message(&message);
                this.stream.stopped = true;
                return Poll::Ready(Err(std::io::Error::new(ErrorKind::Other, alert)));
            }

            // Handle the recieved message
            if let Err(err) = this.handle_message(message) {
                // Handle writing alerts
                if let Some(alert) = err
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<AlertError>())
                {
                    this.stream.write_alert(*alert)
                }

                return Poll::Ready(Err(err));
            }
        }

        // No more handlers, connection is complete
        Poll::Ready(Ok(()))
    }
}

impl<'a> Handshaking<'a> {
    /// Creates the state for a handshake from the server
    /// perspective
    pub fn create_server(
        stream: &'a mut BlazeStream,
        server_data: Arc<BlazeServerContext>,
    ) -> Handshaking<'a> {
        Self {
            stream,
            transcript: Default::default(),
            joiner: Default::default(),
            handler: Some(Box::new(server::ExpectClientHello { server_data })),
        }
    }

    /// Creates the state for a handshake from the client
    /// perspective
    pub fn create_client(stream: &'a mut BlazeStream) -> Handshaking<'a> {
        let client_random: SSLRandom = SSLRandom::random();

        let mut state = Self {
            stream,
            transcript: Default::default(),
            joiner: Default::default(),
            handler: Some(Box::new(client::ExpectServerHello {
                client_random: client_random.clone(),
            })),
        };

        // Write the initial client hello message
        state.write_handshake(HandshakeMessage::new(
            HandshakeType::ClientHello,
            ClientHello {
                random: client_random,
                cipher_suites: vec![
                    CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
                    CipherSuite::TLS_RSA_WITH_RC4_128_MD5,
                ],
            },
        ));

        state
    }

    /// Handles an incoming message and passing the message
    /// to the current handler
    pub fn handle_message(&mut self, message: Message) -> std::io::Result<()> {
        // Take the current handler
        let handler = self
            .handler
            .take()
            // (Handler should be checked before calling)
            .expect("Handling message without handler");

        // Handle non handshake messages
        if !matches!(message.message_type, MessageType::Handshake) {
            self.handler = handler.on_message(self, message)?;
            return Ok(());
        }

        // Consume the message frame using the joiner
        self.joiner.consume(message);

        // Try and take a completed handshake message
        let handshake = match self.joiner.next().transpose()? {
            Some(value) => value,
            None => return Ok(()),
        };

        // Don't include finished messages in the transcript
        if matches!(&handshake.ty, HandshakeType::Finished) {
            // Peer has finished
            self.transcript.finish_peer();
        }

        // Add the message bytes to the transcript
        self.transcript.append(&handshake.payload);

        self.handler = handler.on_handshake(self, handshake)?;

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
    pub fn write_handshake(&mut self, message: HandshakeMessage) {
        let is_finished = matches!(message.ty, HandshakeType::Finished);
        let message: Message = message.into();

        if is_finished {
            // The peer transcript ends when a finished message is sent
            self.transcript.finish_peer();
        }

        self.transcript.append(&message.payload);

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
    fn on_message(self: Box<Self>, state: &mut Handshaking, message: Message) -> HandleResult {
        Err(AlertError::fatal(AlertDescription::UnexpectedMessage))
    }

    /// Handles an incoming handshake message. Returns the next [MessageHandler] to use
    fn on_handshake(
        self: Box<Self>,
        state: &mut Handshaking,
        message: HandshakeMessage,
    ) -> HandleResult {
        Err(AlertError::fatal(AlertDescription::UnexpectedMessage))
    }
}
