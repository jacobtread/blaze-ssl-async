use crate::{
    crypto::{
        compute_finished_hashes, create_keys, create_master_key, HashAlgorithm, MacGenerator,
    },
    msg::{
        codec::Codec,
        handshake::*,
        joiner::HandshakeJoiner,
        transcript::MessageTranscript,
        types::{
            AlertDescription, Certificate, CipherSuite, MessageType, ProtocolVersion, SSLRandom,
        },
        Message,
    },
    rc4::{Rc4Decryptor, Rc4Encryptor},
    stream::{BlazeResult, BlazeStream, StreamMode, SERVER_CERTIFICATE, SERVER_KEY},
};
use crypto::rc4::Rc4;
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    rand_core::{OsRng, RngCore},
    PaddingScheme, PublicKey, RsaPublicKey,
};
use std::future::poll_fn;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use x509_cert::{der::Decode, Certificate as X509Certificate};

/// Stream wrapper which handles handshaking behavior for clients and servers
pub(crate) struct HandshakingWrapper<S> {
    stream: BlazeStream<S>,
    transcript: MessageTranscript,
    joiner: HandshakeJoiner,
    mode: StreamMode,
}

impl<S> HandshakingWrapper<S> {
    pub fn into_inner(self) -> BlazeStream<S> {
        self.stream
    }
}

macro_rules! expect_handshake {
    ($self:ident, $name:ident) => {
        match $self.next_handshake().await? {
            HandshakePayload::$name(value) => value,
            _ => return Err($self.stream.fatal_unexpected()),
        }
    };
}

impl<S> HandshakingWrapper<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Creates a new handshaking wrapper for the provided stream
    pub fn new(stream: BlazeStream<S>, mode: StreamMode) -> HandshakingWrapper<S> {
        Self {
            stream,
            mode,
            transcript: MessageTranscript::default(),
            joiner: HandshakeJoiner::default(),
        }
    }

    /// Completes the handshaking process for the provided side
    pub async fn handshake(&mut self) -> BlazeResult<()> {
        match self.mode {
            StreamMode::Server => {
                let client_random = self.expect_client_hello().await?;
                let server_random = self.emit_server_hello().await?;
                self.emit_certificate().await?;
                self.emit_server_hello_done().await?;
                let pm_secret = self.expect_key_exchange().await?;

                let master_key = create_master_key(&pm_secret, &client_random, &server_random);
                // Server will always use the Sha1 hash algorithm
                let keys = create_keys(
                    &master_key,
                    &client_random,
                    &server_random,
                    HashAlgorithm::Sha1,
                );

                self.expect_change_cipher_spec(keys.client_key, keys.client_mac)
                    .await?;
                self.expect_finished(&master_key).await?;

                self.emit_change_cipher_spec(keys.server_key, keys.server_mac)
                    .await?;
                self.emit_finished(&master_key).await?;
            }
            StreamMode::Client => {
                let client_random = self.emit_client_hello().await?;
                let (server_random, alg) = self.expect_server_hello().await?;
                let certificate = self.expect_certificate().await?;
                let _ = expect_handshake!(self, ServerHelloDone);
                let pm_secret = self.start_key_exchange(certificate).await?;

                let master_key = create_master_key(&pm_secret, &client_random, &server_random);
                let keys = create_keys(&master_key, &client_random, &server_random, alg);

                self.emit_change_cipher_spec(keys.client_key, keys.client_mac)
                    .await?;

                self.emit_finished(&master_key).await?;
                self.expect_change_cipher_spec(keys.server_key, keys.server_mac)
                    .await?;
                self.expect_finished(&master_key).await?;
            }
        }
        Ok(())
    }

    /// Async wrapper over the next messaging polling function for use
    /// within the async handshaking logic
    async fn next_message(&mut self) -> BlazeResult<Message> {
        poll_fn(|cx| self.stream.poll_next_message(cx)).await
    }

    /// Attempts to retrieve the next handshake payload. If the message is not
    /// a handshake then a fatal alert is sent
    async fn next_handshake(&mut self) -> BlazeResult<HandshakePayload> {
        loop {
            if let Some(joined) = self.joiner.next() {
                let handshake = joined.handshake;
                if matches!(&self.mode, StreamMode::Server)
                    && matches!(&handshake, HandshakePayload::Finished(_))
                {
                    self.transcript.finish();
                }
                self.transcript.push_raw(&joined.payload);
                return Ok(handshake);
            } else {
                let message = self.next_message().await?;
                if message.message_type != MessageType::Handshake {
                    return Err(self.stream.fatal_unexpected());
                }
                self.joiner.consume(message);
            }
        }
    }

    /// Creates a new SSLRandom turning any errors into an IllegalParameter alert
    async fn create_random(&mut self) -> BlazeResult<SSLRandom> {
        SSLRandom::new().map_err(|_| self.stream.alert_fatal(AlertDescription::IllegalParameter))
    }

    /// Appends the message to the transcript along with writing the message
    /// to the streaming and flushing
    async fn write_and_flush(&mut self, message: Message) -> BlazeResult<()> {
        self.transcript.push_message(&message);
        self.stream.write_message(message);
        self.stream.flush().await?;
        Ok(())
    }

    /// Emits a ClientHello message and returns the SSLRandom generates for the hello
    async fn emit_client_hello(&mut self) -> BlazeResult<SSLRandom> {
        let random: SSLRandom = self.create_random().await?;
        let message: Message = HandshakePayload::ClientHello(ClientHello {
            random: random.clone(),
            cipher_suites: vec![
                CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
                CipherSuite::TLS_RSA_WITH_RC4_128_MD5,
            ],
        })
        .into();
        self.write_and_flush(message).await?;
        Ok(random)
    }

    /// Expects the server to provide a ServerHello in the next handshake message
    /// and returns the random from the ServerHello
    async fn expect_server_hello(&mut self) -> BlazeResult<(SSLRandom, HashAlgorithm)> {
        let hello: ServerHello = expect_handshake!(self, ServerHello);
        let cipher: CipherSuite = hello.cipher_suite;
        let alg: HashAlgorithm = match cipher {
            CipherSuite::TLS_RSA_WITH_RC4_128_MD5 => HashAlgorithm::Md5,
            CipherSuite::TLS_RSA_WITH_RC4_128_SHA => HashAlgorithm::Sha1,
            _ => return Err(self.stream.fatal_unexpected()),
        };

        Ok((hello.random, alg))
    }

    /// Expects the client to provide a ClientHello in the next handshake message
    /// and returns the random from the ClientHello
    async fn expect_client_hello(&mut self) -> BlazeResult<SSLRandom> {
        let hello: ClientHello = expect_handshake!(self, ClientHello);
        Ok(hello.random)
    }

    /// Emits a ServerHello message and returns the SSLRandom generates for the hello
    async fn emit_server_hello(&mut self) -> BlazeResult<SSLRandom> {
        let random: SSLRandom = self.create_random().await?;
        let message: Message = HandshakePayload::ServerHello(ServerHello {
            random: random.clone(),
            cipher_suite: CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
        })
        .into();
        self.write_and_flush(message).await?;

        Ok(random)
    }

    /// Emits a Certificate message
    async fn emit_certificate(&mut self) -> BlazeResult<()> {
        let message: Message = HandshakePayload::Certificate(ServerCertificate {
            certificates: vec![SERVER_CERTIFICATE.clone()],
        })
        .into();
        self.write_and_flush(message).await
    }

    /// Emits a ServerHello message and returns the SSLRandom generates for the hello
    async fn emit_server_hello_done(&mut self) -> BlazeResult<()> {
        let message: Message = HandshakePayload::ServerHelloDone(ServerHelloDone).into();
        self.write_and_flush(message).await
    }

    /// Expects a certificate from the server returning the first certificate
    /// that the server provides
    async fn expect_certificate(&mut self) -> BlazeResult<Certificate> {
        let certs = expect_handshake!(self, Certificate);
        let first = certs
            .certificates
            .into_iter()
            .next()
            .ok_or_else(|| self.stream.fatal_unexpected())?;
        Ok(first)
    }

    /// Begins the key exchange from the client perspective:
    /// Generates pre master key and sends it to the server
    /// returning the generated pre-master key
    async fn start_key_exchange(&mut self, cert: Certificate) -> BlazeResult<[u8; 48]> {
        let mut rng = OsRng;
        // pre-master secret
        let mut pm_secret = [0u8; 48];
        pm_secret[0..2].copy_from_slice(&ProtocolVersion::SSLv3.encode_vec());
        rng.fill_bytes(&mut pm_secret[2..]);

        let x509 = X509Certificate::from_der(&cert.0).map_err(|_| self.stream.fatal_illegal())?;

        let pb_key_info = x509.tbs_certificate.subject_public_key_info;
        let public_key = RsaPublicKey::from_pkcs1_der(pb_key_info.subject_public_key)
            .map_err(|_| self.stream.fatal_illegal())?;

        let pm_enc = public_key
            .encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, &pm_secret)
            .map_err(|_| self.stream.fatal_illegal())?;

        self.emit_key_exchange(pm_enc).await?;
        Ok(pm_secret)
    }

    /// Emits the ClientKeyExchange method with the provided key exchange bytes
    async fn emit_key_exchange(&mut self, pm_enc: Vec<u8>) -> BlazeResult<()> {
        let message: Message = HandshakePayload::ClientKeyExchange(OpaqueBytes(pm_enc)).into();
        self.write_and_flush(message).await
    }

    async fn expect_key_exchange(&mut self) -> BlazeResult<Vec<u8>> {
        let pm_enc: Vec<u8> = expect_handshake!(self, ClientKeyExchange).0;
        let pm_secret: Vec<u8> = SERVER_KEY
            .decrypt(PaddingScheme::PKCS1v15Encrypt, &pm_enc)
            .map_err(|_| self.stream.fatal_illegal())?;
        Ok(pm_secret)
    }

    async fn emit_change_cipher_spec(&mut self, key: Rc4, mac: MacGenerator) -> BlazeResult<()> {
        let message = Message {
            message_type: MessageType::ChangeCipherSpec,
            payload: vec![1],
        };
        self.stream.write_message(message);
        self.stream.flush().await?;
        self.stream.encryptor = Some(Rc4Encryptor::new(key, mac));
        Ok(())
    }

    async fn expect_change_cipher_spec(&mut self, key: Rc4, mac: MacGenerator) -> BlazeResult<()> {
        match self.next_message().await?.message_type {
            MessageType::ChangeCipherSpec => {}
            _ => return Err(self.stream.fatal_unexpected()),
        }
        self.stream.decryptor = Some(Rc4Decryptor::new(key, mac));
        Ok(())
    }

    async fn emit_finished(&mut self, master_key: &[u8; 48]) -> BlazeResult<()> {
        let (md5_hash, sha_hash) =
            compute_finished_hashes(master_key, &self.mode, self.transcript.current());

        let message: Message = HandshakePayload::Finished(Finished { sha_hash, md5_hash }).into();

        if let StreamMode::Client = &self.mode {
            self.transcript.push_message(&message);
            self.transcript.finish();
        }
        self.stream.write_message(message);
        self.stream.flush().await?;
        Ok(())
    }

    async fn expect_finished(&mut self, master_key: &[u8; 48]) -> BlazeResult<()> {
        let finished: Finished = expect_handshake!(self, Finished);
        let mode: StreamMode = self.mode.invert();
        let (exp_md5_hash, exp_sha_hash) =
            compute_finished_hashes(master_key, &mode, self.transcript.last());
        if exp_md5_hash != finished.md5_hash || exp_sha_hash != finished.sha_hash {
            Err(self.stream.fatal_illegal())
        } else {
            Ok(())
        }
    }
}
