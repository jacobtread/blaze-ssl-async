use crate::msg::types::SSLRandom;
use crate::stream::StreamMode;
use crypto::digest::Digest;
use crypto::md5::Md5;
use crypto::sha1::Sha1;

/// Type alias for a slice of bytes the length of a master key
pub type MasterKey = [u8; 48];
/// Type alias for a key block slice of bytes
pub type KeyBlock = [u8; 80];
/// Type alias for a slice of bytes the length of an Md5 hash
pub type Md5Hash = [u8; 16];
/// Type alias for a slice of bytes to length of an Sha1 hash
pub type Sha1Hash = [u8; 20];

#[derive(Clone, Copy)]
pub enum HashAlgorithm {
    Md5,
    Sha1,
}

impl HashAlgorithm {
    /// Creates a digest for the provided algoritm type
    #[inline]
    pub fn digest(&self) -> Box<dyn Digest> {
        match self {
            Self::Md5 => Box::new(Md5::new()),
            Self::Sha1 => Box::new(Sha1::new()),
        }
    }

    /// Creates slices for the first and second sets of padding
    /// for the specific algoritm type
    #[inline]
    pub fn padding(&self) -> (&[u8], &[u8]) {
        match self {
            Self::Md5 => (&[0x36; 48], &[0x5c; 48]),
            Self::Sha1 => (&[0x36; 40], &[0x5c; 40]),
        }
    }

    /// Returns the hash length for the algorithm
    pub const fn hash_length(&self) -> usize {
        match self {
            Self::Md5 => 16,
            Self::Sha1 => 20,
        }
    }

    /// Computes the mac hash for the provided values
    ///
    /// `write_secret` The session write secret,
    /// `ty`           The type of message
    /// `message`      The message payload
    /// `seq`          The message sequence
    /// `output`       The output to store the hash value at
    fn compute_mac(
        &self,
        write_secret: &[u8],
        ty: u8,
        message: &[u8],
        seq: &u64,
        output: &mut [u8],
    ) {
        let mut digest = self.digest();
        let (pad1, pad2) = self.padding();
        // A = hash(MAC_write_secret + pad_1 + seq_num + SSLCompressed.type + SSLCompressed.length + SSLCompressed.fragment)
        digest.input(write_secret);
        digest.input(pad1);
        digest.input(&seq.to_be_bytes());
        digest.input(&[ty]);
        let length = u16::to_be_bytes(message.len() as u16);
        digest.input(&length);
        digest.input(message);
        digest.result(output);
        digest.reset();

        // hash(MAC_write_secret + pad_2 + A);
        digest.input(write_secret);
        digest.input(pad2);
        digest.input(output);
        digest.result(output);
    }

    /// Computes a finished hash value for using the provided digest and
    /// other values
    ///
    /// `digest`        The hashing digest to use
    /// `master_secret` The master secret value
    /// `sender_value`  The sender value
    /// `transcript`    The transcript to hash
    /// `pad1`          The first padding value
    /// `pad2`          The second padding value
    /// `output`        The output to store the result at
    fn compute_finished_hash(
        &self,
        master_secret: &[u8],
        sender_value: &[u8; 4],
        transcript: &[u8],
        output: &mut [u8],
    ) {
        let mut digest = self.digest();
        let (pad1, pad2) = self.padding();

        digest.input(transcript);
        digest.input(sender_value);
        digest.input(master_secret);
        digest.input(pad1);
        digest.result(output);
        digest.reset();

        digest.input(master_secret);
        digest.input(pad2);
        digest.input(output);
        digest.result(output);
    }
}

/// Mac generator for different hash types. Each value contains
/// the write key for itself
pub enum MacGenerator {
    /// Mac generator for Md5 mac hashes
    Md5(Md5Hash),
    /// Mac generator for Sha1 mac hashes
    Sha1(Sha1Hash),
}

impl MacGenerator {
    pub fn from(alg: &HashAlgorithm, secret: &[u8]) -> Self {
        match alg {
            HashAlgorithm::Md5 => {
                let mut write_secret: Md5Hash = [0u8; 16];
                write_secret.copy_from_slice(secret);
                Self::Md5(write_secret)
            }
            HashAlgorithm::Sha1 => {
                let mut write_secret: Sha1Hash = [0u8; 20];
                write_secret.copy_from_slice(secret);
                Self::Sha1(write_secret)
            }
        }
    }

    /// Validates the mac on the provided payload splitting the mac itself from
    /// the payload
    ///
    /// `payload` The payload to validate
    pub fn validate(&self, payload: &mut Vec<u8>, ty: u8, seq: &u64) -> bool {
        match self {
            Self::Md5(write_secret) => {
                let mac = payload.split_off(payload.len() - 16);
                let mut computed: Md5Hash = [0u8; 16];
                HashAlgorithm::Md5.compute_mac(write_secret, ty, payload, seq, &mut computed);
                mac.eq(&computed)
            }
            Self::Sha1(write_secret) => {
                let mac = payload.split_off(payload.len() - 20);
                let mut computed: Sha1Hash = [0u8; 20];
                HashAlgorithm::Sha1.compute_mac(write_secret, ty, payload, seq, &mut computed);
                mac.eq(&computed)
            }
        }
    }

    /// Computes the mac for a message that is going to be send and appends
    /// the payload to the message
    ///
    /// `payload` The message payload
    /// `ty`      The message type
    /// `seq`     The message sequence
    pub fn append(&self, payload: &mut Vec<u8>, ty: u8, seq: &u64) {
        match self {
            Self::Md5(write_secret) => {
                let mut output: Md5Hash = [0u8; 16];
                HashAlgorithm::Md5.compute_mac(write_secret, ty, payload, seq, &mut output);
                payload.extend_from_slice(&output);
            }
            Self::Sha1(write_secret) => {
                let mut output: Sha1Hash = [0u8; 20];
                HashAlgorithm::Sha1.compute_mac(write_secret, ty, payload, seq, &mut output);
                payload.extend_from_slice(&output);
            }
        }
    }
}

/// Creates a master key from the provided pre master key and
/// client and server randoms
///
/// `pm_key` The pre master key
/// `cr`     The client random
/// `sr`     The server random
pub fn create_master_key(pm_key: &[u8], cr: &SSLRandom, sr: &SSLRandom) -> MasterKey {
    let mut master_key: MasterKey = [0u8; 48];
    generate_key_block(&mut master_key, pm_key, &cr.0, &sr.0);
    master_key
}

/// Length of the keys are always 16 bytes for RC4 keys
const KEY_LENGTH: usize = 16;

pub struct Keys {
    pub client_mac: MacGenerator,
    pub server_mac: MacGenerator,
    pub client_key: [u8; KEY_LENGTH],
    pub server_key: [u8; KEY_LENGTH],
}

pub fn create_keys(
    master_key: &MasterKey,
    cr: &SSLRandom,
    sr: &SSLRandom,
    alg: &HashAlgorithm,
) -> Keys {
    // Generate key block 80 bytes long (20x2 for write secrets + 16x2 for write keys) only 72 bytes used
    let mut key_block = [0u8; 80];
    generate_key_block(&mut key_block, master_key, &sr.0, &cr.0);

    let hash_length = alg.hash_length();
    let (client_write_secret, key_block) = key_block.split_at(hash_length);
    let (server_write_secret, key_block) = key_block.split_at(hash_length);

    let client_mac = MacGenerator::from(alg, client_write_secret);
    let server_mac = MacGenerator::from(alg, server_write_secret);

    let mut client_key = [0u8; KEY_LENGTH];
    client_key.copy_from_slice(&key_block[0..16]);
    let mut server_key = [0u8; KEY_LENGTH];
    server_key.copy_from_slice(&key_block[16..32]);

    Keys {
        client_mac,
        server_mac,
        client_key,
        server_key,
    }
}

/// Generates a key block
fn generate_key_block(out: &mut [u8], pm: &[u8], rand_1: &[u8; 32], rand_2: &[u8; 32]) {
    // The digest use for the outer hash
    let mut outer = Md5::new();
    // The digest used for the inner hash
    let mut inner = Sha1::new();

    let mut randoms = [0u8; 64];
    randoms[..32].copy_from_slice(rand_1);
    randoms[32..].copy_from_slice(rand_2);

    let mut inner_value = [0u8; 20];

    let salts = ["A", "BB", "CCC", "DDDD", "EEEEE"].iter();

    for (chunk, salt) in out.chunks_mut(16).zip(salts) {
        inner.input(salt.as_bytes());
        inner.input(pm);
        inner.input(&randoms);
        inner.result(&mut inner_value);
        inner.reset();

        outer.input(pm);
        outer.input(&inner_value);
        outer.result(chunk);
        outer.reset();
    }
}

/// Computes the finished message hashes for the provided transcript,
/// secret and sender
///
/// `master_secret` The session master secret
/// `sender`        The sender to compute for
/// `transcript`    The transcript to compute hashes with
pub fn compute_finished_hashes(
    master_secret: &[u8],
    sender: &StreamMode,
    transcript: &[u8],
) -> (Md5Hash, Sha1Hash) {
    let sender_value: u32 = match sender {
        StreamMode::Client => 0x434C4E54,
        StreamMode::Server => 0x53525652,
    };
    let sender_value: [u8; 4] = sender_value.to_be_bytes();
    let mut md5_hash: Md5Hash = [0u8; 16];
    HashAlgorithm::Md5.compute_finished_hash(
        master_secret,
        &sender_value,
        transcript,
        &mut md5_hash,
    );
    let mut sha1_hash: Sha1Hash = [0u8; 20];
    HashAlgorithm::Sha1.compute_finished_hash(
        master_secret,
        &sender_value,
        transcript,
        &mut sha1_hash,
    );
    (md5_hash, sha1_hash)
}
