//! Module contains logic and state for completing the
//! SSL handshaking process from a client perspective

use super::{HandleResult, Handshaking, MessageHandler};
use crate::{
    crypto::{
        compute_finished_hashes, create_keys,
        rc4::{Rc4Decryptor, Rc4Encryptor},
        HashAlgorithm, KeyWithMac, MasterKey,
    },
    msg::{
        handshake::{
            CertificateChain, Finished, HandshakeMessage, OpaqueBytes, ServerHello, ServerHelloDone,
        },
        types::{
            AlertDescription, Certificate, CipherSuite, HandshakeType, MessageType, SSLRandom,
        },
        AlertError, Message,
    },
};
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    rand_core::{OsRng, RngCore},
    Pkcs1v15Encrypt, RsaPublicKey,
};
use x509_cert::{der::Decode, Certificate as X509Certificate};

pub(crate) struct ExpectServerHello {
    /// Random data this client is using
    pub(crate) client_random: SSLRandom,
}

impl MessageHandler for ExpectServerHello {
    fn on_handshake(
        self: Box<Self>,
        _state: &mut Handshaking,
        message: HandshakeMessage,
    ) -> HandleResult {
        let server_hello: ServerHello = message.expect_type(HandshakeType::ServerHello)?;
        let alg: HashAlgorithm = match server_hello.cipher_suite {
            CipherSuite::TLS_RSA_WITH_RC4_128_MD5 => HashAlgorithm::Md5,
            CipherSuite::TLS_RSA_WITH_RC4_128_SHA => HashAlgorithm::Sha1,
            _ => return Err(AlertError::fatal(AlertDescription::HandshakeFailure)),
        };

        Ok(Some(Box::new(ExpectCertificate {
            client_random: self.client_random,
            server_random: server_hello.random,
            alg,
        })))
    }
}

struct ExpectCertificate {
    client_random: SSLRandom,
    server_random: SSLRandom,
    alg: HashAlgorithm,
}

impl MessageHandler for ExpectCertificate {
    fn on_handshake(
        self: Box<Self>,
        _state: &mut Handshaking,
        message: HandshakeMessage,
    ) -> HandleResult {
        let CertificateChain(certs) = message.expect_type(HandshakeType::Certificate)?;

        // Choose the first certificate or give an error1
        let certificate = certs
            .into_iter()
            .next()
            .ok_or(AlertError::fatal(AlertDescription::IllegalParameter))?;

        Ok(Some(Box::new(ExpectServerHelloDone {
            client_random: self.client_random,
            server_random: self.server_random,
            alg: self.alg,
            certificate,
        })))
    }
}

struct ExpectServerHelloDone {
    client_random: SSLRandom,
    server_random: SSLRandom,
    alg: HashAlgorithm,
    certificate: Certificate,
}

impl MessageHandler for ExpectServerHelloDone {
    fn on_handshake(
        self: Box<Self>,
        state: &mut Handshaking,
        message: HandshakeMessage,
    ) -> HandleResult {
        let _: ServerHelloDone = message.expect_type(HandshakeType::ServerHelloDone)?;

        let mut rng = OsRng;

        // Generate the pre master secret
        let mut pm_secret = [0u8; 48];
        // SSLv3 protocol version as first 2 secret bytes
        pm_secret[0..2].copy_from_slice(&[3, 0]);
        rng.fill_bytes(&mut pm_secret[2..]);

        // Parse the x509 certificate
        let x509 = X509Certificate::from_der(&self.certificate.0)
            .map_err(|_| AlertError::fatal(AlertDescription::IllegalParameter))?;

        // Create the public key from the certificate
        let public_key = RsaPublicKey::from_pkcs1_der(
            x509.tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )
        .map_err(|_| AlertError::fatal(AlertDescription::IllegalParameter))?;

        // Encrypt the pre master secret
        let pm_encrypted = public_key
            .encrypt(&mut rng, Pkcs1v15Encrypt, &pm_secret)
            .map_err(|_| AlertError::fatal(AlertDescription::IllegalParameter))?;

        // Begin the server key exchange
        state.write_handshake(HandshakeMessage::new(
            HandshakeType::ClientKeyExchange,
            OpaqueBytes(pm_encrypted),
        ));

        // Create the keys to use
        let keys = create_keys(
            &pm_secret,
            &self.client_random,
            &self.server_random,
            self.alg,
        );

        // Emit the change of cipher
        state.write_message(Message {
            message_type: MessageType::ChangeCipherSpec,
            payload: vec![1],
        });

        // Switch the stream to use the server encryption
        state.stream.encryptor = Some(Rc4Encryptor::new(keys.client.key, keys.client.mac));

        // Write the finished message
        let finished = compute_finished_hashes(&keys.master_key, true, state.transcript.current());
        state.write_handshake(HandshakeMessage::new(HandshakeType::Finished, finished));

        Ok(Some(Box::new(ExpectChangeCipherSpec {
            master_key: keys.master_key,
            server_key: keys.server,
        })))
    }
}

/// Server version of expecting a change in the cipher spec
struct ExpectChangeCipherSpec {
    master_key: MasterKey,
    server_key: KeyWithMac,
}

impl MessageHandler for ExpectChangeCipherSpec {
    fn on_message(self: Box<Self>, state: &mut Handshaking, message: Message) -> HandleResult {
        // Expecting a change cipher spec message
        let MessageType::ChangeCipherSpec = message.message_type else {
            return Err(AlertError::fatal(AlertDescription::UnexpectedMessage));
        };

        // Switch the stream to use the server encryption
        state.stream.decryptor = Some(Rc4Decryptor::new(self.server_key.key, self.server_key.mac));

        Ok(Some(Box::new(ExpectServerFinished {
            master_key: self.master_key,
        })))
    }
}

/// Handles expecting the finished message from the client,
/// changing the cipher spec, and emitting the server finished
struct ExpectServerFinished {
    /// The master key
    master_key: MasterKey,
}

impl MessageHandler for ExpectServerFinished {
    fn on_handshake(
        self: Box<Self>,
        state: &mut Handshaking,
        message: HandshakeMessage,
    ) -> HandleResult {
        let finished: Finished = message.expect_type(HandshakeType::Finished)?;
        let expected = compute_finished_hashes(&self.master_key, false, state.transcript.peer());

        // Ensure the finished hashes match
        if finished != expected {
            return Err(AlertError::fatal(AlertDescription::IllegalParameter));
        }

        Ok(None)
    }
}
