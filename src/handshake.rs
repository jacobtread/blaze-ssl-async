use super::{
    crypto::*,
    msg::{
        handshake::*, joiner::HandshakeJoiner, transcript::MessageTranscript, types::*, Message,
    },
    rc4::Rc4,
    stream::*,
};
use rsa::{
    pkcs1::DecodeRsaPublicKey,
    rand_core::{OsRng, RngCore},
    PaddingScheme, PublicKey, RsaPublicKey,
};
use std::future::poll_fn;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use x509_cert::{der::Decode, Certificate as X509Certificate};

/// Wrapper over a BlazeStream for completing the handshaking portion
/// of the connection using a async await syntax
pub(crate) struct HandshakingWrapper<S> {
    /// The wrapped stream
    stream: BlazeStream<S>,
    /// The handshake message transcript
    transcript: MessageTranscript,
    /// The handshake message joiner
    joiner: HandshakeJoiner,
    /// The stream type
    ty: StreamType,
}

impl<S> HandshakingWrapper<S> {
    /// Converts the wrapper into its wrapped stream
    pub fn into_inner(self) -> BlazeStream<S> {
        self.stream
    }
    /// Creates a new handshaking wrapper for the provided stream with
    /// the provided type
    ///
    /// `stream` The stream to wrap
    /// `ty`   The type of the stream
    pub fn new(stream: BlazeStream<S>, ty: StreamType) -> HandshakingWrapper<S> {
        Self {
            stream,
            ty,
            transcript: Default::default(),
            joiner: Default::default(),
        }
    }
}

/// Macro for expecting the next handshake to be of a specific
/// type throwing a fatal unexpected error if the message was
/// not the correct type
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
    /// Completes the handshaking process for which ever type of
    /// stream we have
    pub async fn handshake(&mut self) -> BlazeResult<()> {
        match &self.ty {
            StreamType::Server { .. } => self.handshake_server().await,
            StreamType::Client => self.handshake_client().await,
        }
    }

    /// Completes the handshaking process from the persepective
    /// of a server stream
    async fn handshake_server(&mut self) -> BlazeResult<()> {
        let client_random = self.expect_client_hello().await?;
        let server_random = self.emit_server_hello().await?;
        self.emit_certificate().await?;
        self.emit_server_hello_done().await?;
        let pm_secret = self.expect_key_exchange().await?;

        // Server will always use the Sha1 hash algorithm
        let keys = create_keys(
            &pm_secret,
            client_random,
            server_random,
            HashAlgorithm::Sha1,
        );

        self.expect_change_cipher_spec(keys.client_key, keys.client_mac)
            .await?;
        self.expect_finished(&keys.master_key).await?;

        self.emit_change_cipher_spec(keys.server_key, keys.server_mac)
            .await?;
        self.emit_finished(&keys.master_key).await?;
        Ok(())
    }

    /// Completes the handshaking process from the perespective
    /// of a client stream
    async fn handshake_client(&mut self) -> BlazeResult<()> {
        let client_random = self.emit_client_hello().await?;
        let (server_random, alg) = self.expect_server_hello().await?;
        let certificate = self.expect_certificate().await?;
        let _ = expect_handshake!(self, ServerHelloDone);
        let pm_secret = self.start_key_exchange(certificate).await?;

        let keys = create_keys(&pm_secret, client_random, server_random, alg);

        self.emit_change_cipher_spec(keys.client_key, keys.client_mac)
            .await?;

        self.emit_finished(&keys.master_key).await?;
        self.expect_change_cipher_spec(keys.server_key, keys.server_mac)
            .await?;
        self.expect_finished(&keys.master_key).await?;
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
                if matches!(
                    (&self.ty, &handshake),
                    (StreamType::Server { .. }, HandshakePayload::Finished(_))
                ) {
                    self.transcript.finish();
                }
                self.transcript.push_raw(&joined.payload);
                return Ok(handshake);
            } else {
                let message = self.next_message().await?;

                // Error when getting Non handshaking messages when expecting
                if let MessageType::Handshake = message.message_type {
                    self.joiner.consume(message);
                } else {
                    return Err(self.stream.fatal_unexpected());
                }
            }
        }
    }

    /// Appends the message to the transcript along with writing the message
    /// to the streaming and flushing
    ///
    /// `message` The message to write and flush
    async fn write_and_flush(&mut self, message: Message) -> BlazeResult<()> {
        // Only append handshakes to the transcript
        if let MessageType::Handshake = message.message_type {
            self.transcript.push_message(&message);
        }
        self.stream.write_message(message);
        self.stream.flush().await?;
        Ok(())
    }

    /// Emits a ClientHello message with the cipher suites supported by this
    /// server using. Creates a client random value which is included in the
    /// message and returned
    async fn emit_client_hello(&mut self) -> BlazeResult<SSLRandom> {
        let random: SSLRandom = SSLRandom::default();
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
        let alg: HashAlgorithm = match hello.cipher_suite {
            CipherSuite::TLS_RSA_WITH_RC4_128_MD5 => HashAlgorithm::Md5,
            CipherSuite::TLS_RSA_WITH_RC4_128_SHA => HashAlgorithm::Sha1,
            _ => return Err(self.stream.fatal_illegal()),
        };

        Ok((hello.random, alg))
    }

    /// Expects the client to provide a ClientHello in the next handshake message
    /// and returns the random from the ClientHello
    async fn expect_client_hello(&mut self) -> BlazeResult<SSLRandom> {
        let hello: ClientHello = expect_handshake!(self, ClientHello);
        Ok(hello.random)
    }

    /// Emits a ServerHello message and returns the SSLRandom generated for the hello
    async fn emit_server_hello(&mut self) -> BlazeResult<SSLRandom> {
        let random: SSLRandom = SSLRandom::default();
        let message: Message = HandshakePayload::ServerHello(ServerHello {
            random: random.clone(),
            cipher_suite: CipherSuite::TLS_RSA_WITH_RC4_128_SHA,
        })
        .into();
        self.write_and_flush(message).await?;
        Ok(random)
    }

    /// Emits a Certificate message containing the server certificate
    async fn emit_certificate(&mut self) -> BlazeResult<()> {
        let server_data = self.ty.server_data();
        let message: Message =
            HandshakePayload::Certificate(ServerCertificate::Send(server_data.certificate.clone()))
                .into();
        self.write_and_flush(message).await
    }

    /// Emits a ServerHelloDone message indicate the server hello has finished
    async fn emit_server_hello_done(&mut self) -> BlazeResult<()> {
        let message: Message = HandshakePayload::ServerHelloDone(ServerHelloDone).into();
        self.write_and_flush(message).await
    }

    /// Expects a certificate from the server returning the first certificate
    /// that the server provides or a fatal unexpected error if there were none
    async fn expect_certificate(&mut self) -> BlazeResult<Certificate> {
        if let ServerCertificate::Recieve(certs) = expect_handshake!(self, Certificate) {
            let first = certs
                .into_iter()
                .next()
                .ok_or_else(|| self.stream.fatal_illegal())?;
            Ok(first)
        } else {
            // Not possible to encounter
            panic!("Got send certificate while expecting recieve")
        }
    }

    /// Begins the key exchange from the client perspective:
    /// Generates pre master key and sends it to the server
    /// returning the generated pre-master key. Sending a
    /// ClientKeyExchange message to the client
    ///
    /// `cert` The certificate to use for the exchange
    async fn start_key_exchange(&mut self, cert: Certificate) -> BlazeResult<[u8; 48]> {
        let mut rng = OsRng;

        // Generate the pre master secret
        let mut pm_secret = [0u8; 48];
        // SSLv3 protocol version as first 2 secret bytes
        pm_secret[0..2].copy_from_slice(&[3, 0]);
        rng.fill_bytes(&mut pm_secret[2..]);

        // Parse the x509 certificate
        let x509 = X509Certificate::from_der(&cert.0).map_err(|_| self.stream.fatal_illegal())?;

        // Create the public key from the certificate
        let public_key = RsaPublicKey::from_pkcs1_der(
            x509.tbs_certificate
                .subject_public_key_info
                .subject_public_key,
        )
        .map_err(|_| self.stream.fatal_illegal())?;

        // Encrypt the pre master secret
        let pm_enc = public_key
            .encrypt(&mut rng, PaddingScheme::PKCS1v15Encrypt, &pm_secret)
            .map_err(|_| self.stream.fatal_illegal())?;

        // Send the key exchange message
        let message: Message = HandshakePayload::ClientKeyExchange(OpaqueBytes(pm_enc)).into();
        self.write_and_flush(message).await?;
        Ok(pm_secret)
    }

    /// Expects a key exchange message from the server decrypts
    /// the pre master secret from the message returning the
    /// pre master secret.
    async fn expect_key_exchange(&mut self) -> BlazeResult<Vec<u8>> {
        let pm_enc: Vec<u8> = expect_handshake!(self, ClientKeyExchange).0;
        let server_data = self.ty.server_data();
        // Decrypt the pre master secret
        let pm_secret: Vec<u8> = server_data
            .private_key
            .decrypt(PaddingScheme::PKCS1v15Encrypt, &pm_enc)
            .map_err(|_| self.stream.fatal_illegal())?;
        Ok(pm_secret)
    }

    /// Emits the change cipher spec message indicating and
    /// sets the encryptor to use the provided key and mac
    /// generator
    ///
    /// `key` The key to use
    /// `mac` The mac generator to use
    async fn emit_change_cipher_spec(&mut self, key: Rc4, mac: MacGenerator) -> BlazeResult<()> {
        // Send the change cipher spec messsage
        let message = Message {
            message_type: MessageType::ChangeCipherSpec,
            payload: vec![1],
        };
        self.write_and_flush(message).await?;
        // Update to encryptor
        self.stream.set_encryptor(key, mac);
        Ok(())
    }

    /// Expects a change cipher spec from the opposite side and
    /// sets the stream decryptor using the provided key and mac
    /// generator once the change cipher spec message is recieved
    ///
    /// `key` The key to use
    /// `mac` The mac generator to use
    async fn expect_change_cipher_spec(&mut self, key: Rc4, mac: MacGenerator) -> BlazeResult<()> {
        match self.next_message().await?.message_type {
            MessageType::ChangeCipherSpec => {}
            _ => return Err(self.stream.fatal_unexpected()),
        }
        self.stream.set_decryptor(key, mac);
        Ok(())
    }

    /// Emits the finished message generating the finished hashes from the
    /// current transcript portion
    ///
    /// `master_key` The master key for computing the transcript hash
    async fn emit_finished(&mut self, master_key: &[u8; 48]) -> BlazeResult<()> {
        let (md5_hash, sha_hash) =
            compute_finished_hashes(master_key, self.ty.is_client(), self.transcript.current());
        let message: Message = HandshakePayload::Finished(Finished { sha_hash, md5_hash }).into();
        if let StreamType::Client = &self.ty {
            self.transcript.push_message(&message);
            self.transcript.finish();
        }
        self.stream.write_message(message);
        self.stream.flush().await?;
        Ok(())
    }

    /// Expects the finished message generating the finished hashes for opposite
    /// side using the last transcript portion comparing the hashes to ensure they
    /// match
    ///
    /// `master_key` The master key for computing the transcript hash
    async fn expect_finished(&mut self, master_key: &[u8; 48]) -> BlazeResult<()> {
        let finished: Finished = expect_handshake!(self, Finished);
        let (exp_md5_hash, exp_sha_hash) =
            compute_finished_hashes(master_key, !self.ty.is_client(), self.transcript.last());
        if exp_md5_hash != finished.md5_hash || exp_sha_hash != finished.sha_hash {
            Err(self.stream.fatal_illegal())
        } else {
            Ok(())
        }
    }
}
