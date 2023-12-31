//! Module contains logic and state for completing the
//! SSL handshaking process from a server perspective

use super::{HandleResult, Handshaking, MessageHandler};
use crate::{
    crypto::{
        compute_finished_hashes, create_keys,
        rc4::{Rc4Decryptor, Rc4Encryptor},
        HashAlgorithm, KeyWithMac, MasterKey,
    },
    listener::BlazeServerContext,
    msg::{
        handshake::{
            CertificateChain, ClientHello, Finished, HandshakeMessage, OpaqueBytes, ServerHello,
            ServerHelloDone,
        },
        types::{AlertDescription, CipherSuite, HandshakeType, MessageType, SSLRandom},
        AlertError, Message,
    },
};
use rsa::Pkcs1v15Encrypt;
use std::sync::Arc;

/// Handles expecting a ClientHello message then responding
/// with the server credentials and completing the hello
pub(crate) struct ExpectClientHello {
    /// Shared server data containing the private key and
    /// server certificate chain
    pub(crate) server_data: Arc<BlazeServerContext>,
}

impl MessageHandler for ExpectClientHello {
    fn on_handshake(
        self: Box<Self>,
        state: &mut Handshaking,
        message: HandshakeMessage,
    ) -> HandleResult {
        let client_hello: ClientHello = message.expect_type(HandshakeType::ClientHello)?;

        let client_random: SSLRandom = client_hello.random;
        let server_random: SSLRandom = SSLRandom::random();

        // Write the server hello message
        state.write_handshake(HandshakeMessage::new(
            HandshakeType::ServerHello,
            ServerHello {
                random: server_random.clone(),
                cipher_suite: CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
            },
        ));

        // Write the server certificate chain
        let certificates = self.server_data.certificate_chain.clone();
        state.write_handshake(HandshakeMessage::new(
            HandshakeType::Certificate,
            CertificateChain(certificates),
        ));

        // Write the hello done message
        state.write_handshake(HandshakeMessage::new(
            HandshakeType::ServerHelloDone,
            ServerHelloDone,
        ));

        // Move to the key exchange handler
        Ok(Some(Box::new(ExpectKeyExchange {
            server_data: self.server_data.clone(),
            client_random,
            server_random,
        })))
    }
}

/// Expects a ClientKeyExchange message to begin exchanging keys
struct ExpectKeyExchange {
    /// Shared server data containing the private key and
    /// server certificate chain
    server_data: Arc<BlazeServerContext>,
    /// Client random bytes
    client_random: SSLRandom,
    /// Server random bytes
    server_random: SSLRandom,
}

impl MessageHandler for ExpectKeyExchange {
    fn on_handshake(
        self: Box<Self>,
        _state: &mut Handshaking,
        message: HandshakeMessage,
    ) -> HandleResult {
        // Get the encrypted pre master secret
        let OpaqueBytes(pm_encrypted) = message.expect_type(HandshakeType::ClientKeyExchange)?;

        // Decrypt the pre master secret
        let pm_secret: Vec<u8> = self
            .server_data
            .private_key
            .decrypt(Pkcs1v15Encrypt, &pm_encrypted)
            .map_err(|_| AlertError::fatal(AlertDescription::IllegalParameter))?;

        // Create the keys (Server always uses SHA1 hashing algorithm)
        let keys = create_keys(
            &pm_secret,
            &self.client_random,
            &self.server_random,
            HashAlgorithm::Sha1,
        );

        Ok(Some(Box::new(ExpectChangeCipherSpec {
            master_key: keys.master_key,
            client_key: keys.client,
            server_key: keys.server,
        })))
    }
}

/// Server version of expecting a change in the cipher spec
struct ExpectChangeCipherSpec {
    master_key: MasterKey,
    client_key: KeyWithMac,
    server_key: KeyWithMac,
}

impl MessageHandler for ExpectChangeCipherSpec {
    fn on_message(self: Box<Self>, state: &mut Handshaking, message: Message) -> HandleResult {
        // Expecting a change cipher spec message
        let MessageType::ChangeCipherSpec = message.message_type else {
            return Err(AlertError::fatal(AlertDescription::UnexpectedMessage));
        };

        // Switch the stream to use the client encryption
        state.stream.decryptor = Some(Rc4Decryptor::new(self.client_key.key, self.client_key.mac));

        Ok(Some(Box::new(ExpectClientFinished {
            master_key: self.master_key,
            server_key: self.server_key,
        })))
    }
}

/// Handles expecting the finished message from the client,
/// changing the cipher spec, and emitting the server finished
struct ExpectClientFinished {
    /// The master key
    master_key: MasterKey,
    /// The key to switch to after emitting a change cipher spec
    server_key: KeyWithMac,
}

impl MessageHandler for ExpectClientFinished {
    fn on_handshake(
        self: Box<Self>,
        state: &mut Handshaking,
        message: HandshakeMessage,
    ) -> HandleResult {
        let finished: Finished = message.expect_type(HandshakeType::Finished)?;
        let expected = compute_finished_hashes(&self.master_key, true, state.transcript.peer());

        // Ensure the finished hashes match
        if finished != expected {
            return Err(AlertError::fatal(AlertDescription::IllegalParameter));
        }

        // Write the cipher spec change message
        state.write_message(Message::new(MessageType::ChangeCipherSpec, vec![1]));

        // Switch the stream to use the server encryption
        state.stream.encryptor = Some(Rc4Encryptor::new(self.server_key.key, self.server_key.mac));

        // Write the finished message
        let finished = compute_finished_hashes(&self.master_key, false, state.transcript.current());
        state.write_handshake(HandshakeMessage::new(HandshakeType::Finished, finished));

        Ok(None)
    }
}
