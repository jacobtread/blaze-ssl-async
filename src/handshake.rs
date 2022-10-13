use crypto::rc4::Rc4;
pub use crate::msg::handshake::*;
use crate::msg::{AlertDescription, Certificate, CipherSuite, Codec, HandshakeJoiner, Message, MessageTranscript, MessageType, ProtocolVersion, SSLRandom};
use crate::stream::{BlazeResult, BlazeStream, ReadProcessor, SERVER_CERTIFICATE, SERVER_KEY, WriteProcessor};
use std::io::{Read, Write};
use der::Decode;
use rsa::rand_core::{OsRng, RngCore};
use rsa::{BigUint, PaddingScheme, PublicKey, RsaPublicKey};
use x509_cert::Certificate as X509Certificate;
use crate::crypto::{compute_finished_md5, compute_finished_sha, create_crypto_state, CryptographicState, FinishedSender};

/// Stream wrapper which handles handshaking behavior for clients and servers
pub(crate) struct HandshakingWrapper<S> {
    stream: BlazeStream<S>,
    transcript: MessageTranscript,
    joiner: HandshakeJoiner,
    side: HandshakeSide,
}

#[derive(Debug)]
pub enum HandshakeSide {
    /// Handshaking from a server perspective
    Server,
    /// Handshaking from a client perspective
    Client,
}

impl<S> HandshakingWrapper<S>
    where
        S: Read + Write,
{
    /// Creates a new handshaking wrapper for the provided stream
    pub fn new(stream: BlazeStream<S>, side: HandshakeSide) -> HandshakingWrapper<S> {
        Self {
            stream,
            transcript: MessageTranscript::new(),
            joiner: HandshakeJoiner::new(),
            side,
        }
    }

    /// Completes the handshaking process for the provided side
    pub fn handshake(mut self) -> BlazeResult<BlazeStream<S>> {
        match self.side {
            HandshakeSide::Server => {
                let client_random = self.expect_client_hello()?;
                let server_random = self.emit_server_hello()?;
                self.emit_certificate()?;
                self.emit_server_hello_done()?;
                let pm_secret = self.expect_key_exchange()?;
                let crypto_state = create_crypto_state(&pm_secret, &client_random.0, &server_random.0);
                self.expect_change_cipher_spec(&crypto_state)?;
                self.expect_finished(&crypto_state)?;
                self.emit_change_cipher_spec(&crypto_state)?;
                self.emit_finished(&crypto_state)?;
            }
            HandshakeSide::Client => {
                let client_random = self.emit_client_hello()?;
                let server_random = self.expect_server_hello()?;
                let certificate = self.expect_certificate()?;
                self.expect_server_hello_done()?;
                let pm_secret = self.start_key_exchange(certificate)?;
                let crypto_state = create_crypto_state(&pm_secret, &client_random.0, &server_random.0);
                self.emit_change_cipher_spec(&crypto_state)?;
                self.emit_finished(&crypto_state)?;
                self.expect_change_cipher_spec(&crypto_state)?;
                self.expect_finished(&crypto_state)?;
            }
        }
        Ok(self.stream)
    }

    /// Attempts to retrieve the next handshake payload. If the message is not
    /// a handshake then a fatal alert is sent
    fn next_handshake(&mut self) -> BlazeResult<HandshakePayload> {
        loop {
            if let Some(joined) = self.joiner.next() {
                let handshake = joined.handshake;
                if matches!(&self.side, HandshakeSide::Server) && matches!(&handshake, HandshakePayload::Finished(_)) {
                    self.transcript.finish();
                }
                self.transcript.push_raw(&joined.payload);
                return Ok(handshake);
            } else {
                let message = self.stream.next_message()?;
                if message.message_type != MessageType::Handshake {
                    return Err(self.stream.fatal_unexpected());
                }
                self.joiner.consume(message);
            }
        }
    }

    /// Creates a new SSLRandom turning any errors into an IllegalParameter alert
    fn create_random(&mut self) -> BlazeResult<SSLRandom> {
        SSLRandom::new()
            .map_err(|_| self.stream.alert_fatal(AlertDescription::IllegalParameter))
    }

    /// Emits a ClientHello message and returns the SSLRandom generates for the hello
    fn emit_client_hello(&mut self) -> BlazeResult<SSLRandom> {
        let random = self.create_random()?;
        let message = HandshakePayload::ClientHello(ClientHello {
            random: random.clone(),
            cipher_suites: vec![
                CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
                CipherSuite::TLS_RSA_WITH_RC4_128_MD5,
            ],
        }).as_message();
        self.transcript.push_message(&message);
        self.stream.write_message(message)?;
        return Ok(random);
    }

    /// Expects the server to provide a ServerHello in the next handshake message
    /// and returns the random from the ServerHello
    fn expect_server_hello(&mut self) -> BlazeResult<SSLRandom> {
        match self.next_handshake()? {
            HandshakePayload::ServerHello(hello) => Ok(hello.random),
            _ => return Err(self.stream.fatal_unexpected()),
        }
    }

    /// Expects the client to provide a ClientHello in the next handshake message
    /// and returns the random from the ClientHello
    fn expect_client_hello(&mut self) -> BlazeResult<SSLRandom> {
        match self.next_handshake()? {
            HandshakePayload::ClientHello(hello) => Ok(hello.random),
            _ => return Err(self.stream.fatal_unexpected()),
        }
    }

    /// Emits a ServerHello message and returns the SSLRandom generates for the hello
    fn emit_server_hello(&mut self) -> BlazeResult<SSLRandom> {
        let random = self.create_random()?;
        let message = HandshakePayload::ServerHello(ServerHello {
            random: random.clone(),
            cipher_suite: CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
        }).as_message();
        self.transcript.push_message(&message);
        self.stream.write_message(message)?;
        return Ok(random);
    }

    /// Emits a Certificate message
    fn emit_certificate(&mut self) -> BlazeResult<()> {
        let message = HandshakePayload::Certificate(ServerCertificate {
            certificates: vec![SERVER_CERTIFICATE.clone()]
        }).as_message();
        self.transcript.push_message(&message);
        self.stream.write_message(message)?;
        return Ok(());
    }

    /// Emits a ServerHello message and returns the SSLRandom generates for the hello
    fn emit_server_hello_done(&mut self) -> BlazeResult<()> {
        let message = HandshakePayload::ServerHelloDone(ServerHelloDone).as_message();
        self.transcript.push_message(&message);
        self.stream.write_message(message)?;
        return Ok(());
    }

    /// Expects a certificate from the server returning the first certificate
    /// that the server provides
    fn expect_certificate(&mut self) -> BlazeResult<Certificate> {
        match self.next_handshake()? {
            HandshakePayload::Certificate(certs) => {
                let certs = certs.certificates;
                if certs.is_empty() {
                    return Err(self.stream.fatal_unexpected());
                }
                Ok(certs[0].clone())
            }
            _ => return Err(self.stream.fatal_unexpected()),
        }
    }

    /// Expects the server to provide a ServerHelloDone in the next handshake message
    fn expect_server_hello_done(&mut self) -> BlazeResult<()> {
        match self.next_handshake()? {
            HandshakePayload::ServerHelloDone(_) => Ok(()),
            _ => return Err(self.stream.fatal_unexpected()),
        }
    }

    /// Begins the key exchange from the client perspective:
    /// Generates pre master key and sends it to the server
    /// returning the generated pre-master key
    fn start_key_exchange(
        &mut self,
        cert: Certificate,
    ) -> BlazeResult<[u8; 48]> {
        let mut rng = OsRng;
        // pre-master secret
        let mut pm_secret = [0u8; 48];
        pm_secret[0..2].copy_from_slice(&ProtocolVersion::SSLv3.encode_vec());
        rng.fill_bytes(&mut pm_secret[2..]);

        let x509 = X509Certificate::from_der(&cert.0)
            .map_err(|_| self.stream.fatal_illegal())?;

        let pb_key_info = x509.tbs_certificate.subject_public_key_info;
        let rsa_pub_key = pkcs1::RsaPublicKey::from_der(pb_key_info.subject_public_key)
            .map_err(|_| self.stream.fatal_illegal())?;

        let modulus = BigUint::from_bytes_be(rsa_pub_key.modulus.as_bytes());
        let public_exponent = BigUint::from_bytes_be(rsa_pub_key.public_exponent.as_bytes());

        let public_key = RsaPublicKey::new(modulus, public_exponent)
            .map_err(|_| self.stream.fatal_illegal())?;

        let pm_enc = public_key
            .encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, &pm_secret)
            .map_err(|_| self.stream.fatal_illegal())?;
        self.emit_key_exchange(pm_enc)?;
        Ok(pm_secret)
    }

    /// Emits the ClientKeyExchange method with the provided key exchange bytes
    fn emit_key_exchange(&mut self, pm_enc: Vec<u8>) -> BlazeResult<()> {
        let message = HandshakePayload::ClientKeyExchange(OpaqueBytes(pm_enc))
            .as_message();
        self.transcript.push_message(&message);
        self.stream.write_message(message)?;
        Ok(())
    }

    fn expect_key_exchange(&mut self) -> BlazeResult<Vec<u8>> {
        let pm_enc = match self.next_handshake()? {
            HandshakePayload::ClientKeyExchange(b) => b.0,
            _ => return Err(self.stream.fatal_unexpected()),
        };
        let pm_secret = SERVER_KEY
            .decrypt(PaddingScheme::PKCS1v15Encrypt, &pm_enc)
            .map_err(|_| self.stream.fatal_illegal())?;
        Ok(pm_secret)
    }

    fn get_crypto_secrets(&mut self, state: &CryptographicState, is_recv: bool) -> ([u8; 20], Rc4) {
        let (a, b) = match (&self.side, is_recv) {
            (HandshakeSide::Client, true) |
            (HandshakeSide::Server, false)
            => (&state.server_write_secret, &state.server_write_key),
            (HandshakeSide::Client, false) |
            (HandshakeSide::Server, true)
            => (&state.client_write_secret, &state.client_write_key)
        };
        let mut mac_secret = [0u8; 20];
        mac_secret.clone_from(a);
        let key = Rc4::new(b);
        (mac_secret, key)
    }

    fn emit_change_cipher_spec(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        let message = Message {
            message_type: MessageType::ChangeCipherSpec,
            payload: vec![1],
        };
        self.stream.write_message(message)?;
        let (mac_secret, key) = self.get_crypto_secrets(state, false);
        self.stream.write_processor = WriteProcessor::RC4 {
            mac_secret,
            key,
            seq: 0,
        };
        Ok(())
    }

    fn expect_change_cipher_spec(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        match self.stream.next_message()?.message_type {
            MessageType::ChangeCipherSpec => {}
            _ => return Err(self.stream.fatal_unexpected()),
        }
        let (mac_secret, key) = self.get_crypto_secrets(state, true);
        self.stream.read_processor = ReadProcessor::RC4 {
            mac_secret,
            key,
            seq: 0,
        };
        Ok(())
    }

    fn emit_finished(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        let master_key = &state.master_key;
        let sender = match &self.side {
            HandshakeSide::Server => FinishedSender::Server,
            HandshakeSide::Client => FinishedSender::Client
        };
        let md5_hash = compute_finished_md5(master_key, &sender, self.transcript.current());
        let sha_hash = compute_finished_sha(master_key, &sender, self.transcript.current());

        let message = HandshakePayload::Finished(Finished {
            sha_hash,
            md5_hash,
        }).as_message();

        if let HandshakeSide::Client = &self.side {
            self.transcript.push_message(&message);
            self.transcript.finish();
        }
        self.stream.write_message(message)?;
        Ok(())
    }

    fn expect_finished(&mut self, state: &CryptographicState) -> BlazeResult<()> {
        let finished = match self.next_handshake()? {
            HandshakePayload::Finished(p) => p,
            _ => return Err(self.stream.fatal_unexpected()),
        };
        let master_key = &state.master_key;
        let sender = match &self.side {
            HandshakeSide::Server => FinishedSender::Client,
            HandshakeSide::Client => FinishedSender::Server
        };

        let exp_md5_hash = compute_finished_md5(master_key, &sender, self.transcript.last());
        let exp_sha_hash = compute_finished_sha(master_key, &sender, self.transcript.last());

        if exp_md5_hash != finished.md5_hash || exp_sha_hash != finished.sha_hash {
            return Err(self.stream.fatal_illegal());
        }

        Ok(())
    }
}
