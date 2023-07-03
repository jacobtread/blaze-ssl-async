use super::msg::types::{RandomInner, SSLRandom};
use rc4::Rc4;

mod buffer;
mod md5;
pub mod rc4;
mod sha1;

use md5::Md5;
use sha1::Sha1;

/// Type alias for a slice of bytes the length of a master key
pub type MasterKey = [u8; 48];

/// The length of MD5 hashes in bytes
const MD5_HASH_LENGTH: usize = 16;
/// The length of SHA1 hashes in bytes
const SHA1_HASH_LENGTH: usize = 20;

/// The inner padding bytes for MD5 hashing
const MD5_PAD_1: [u8; 48] = [0x36; 48];
/// The outer padding bytes for MD5 hashing
const MD5_PAD_2: [u8; 48] = [0x5c; 48];

/// The inner padding bytes for SHA1 hashing
const SHA1_PAD_1: [u8; 40] = [0x36; 40];
/// The outer padding bytes for SHA1 hashing
const SHA1_PAD_2: [u8; 40] = [0x5c; 40];

/// Type alias for a slice of bytes the length of an Md5 hash
type Md5Hash = [u8; MD5_HASH_LENGTH];
/// Type alias for a slice of bytes to length of an Sha1 hash
type Sha1Hash = [u8; SHA1_HASH_LENGTH];

/// Abstraction from the cipher suite which determines which
/// hashing algorithm is used based on the cipher
pub enum HashAlgorithm {
    /// MD5 Hashing
    Md5,
    /// SHA1 Hashing
    Sha1,
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
    /// Splits a mac generator from the provided key block. Returns the mac
    /// generator and the remaining key block
    ///
    /// # Arguments
    /// * alg - The algorithm to use for mac generation
    /// * key_block - The key block to split
    fn split_key_block<'a>(alg: &HashAlgorithm, key_block: &'a [u8]) -> (Self, &'a [u8]) {
        match alg {
            HashAlgorithm::Md5 => {
                let (secret, key_block) = key_block.split_at(MD5_HASH_LENGTH);
                let mut write_secret: Md5Hash = [0u8; MD5_HASH_LENGTH];
                write_secret.copy_from_slice(secret);
                (Self::Md5(write_secret), key_block)
            }
            HashAlgorithm::Sha1 => {
                let (secret, key_block) = key_block.split_at(SHA1_HASH_LENGTH);
                let mut write_secret: Sha1Hash = [0u8; SHA1_HASH_LENGTH];
                write_secret.copy_from_slice(secret);
                (Self::Sha1(write_secret), key_block)
            }
        }
    }

    /// Computes a mac using the MD5 hashing digest and padding for the
    /// provided message and details
    ///
    /// # Arguments
    /// * write_secret - The mac write secret
    /// * ty - The message type
    /// * message - The message payload
    /// * seq - The message sequence number
    fn compute_md5(write_secret: &[u8], ty: u8, message: &[u8], seq: &u64) -> Md5Hash {
        let mut output: Md5Hash = [0u8; MD5_HASH_LENGTH];
        let mut digest = Md5::new();
        // A = hash(MAC_write_secret + pad_1 + seq_num + SSLCompressed.type + SSLCompressed.length + SSLCompressed.fragment)
        digest.input(write_secret);
        digest.input(&MD5_PAD_1);
        digest.input(&seq.to_be_bytes());
        digest.input(&[ty]);
        let length = u16::to_be_bytes(message.len() as u16);
        digest.input(&length);
        digest.input(message);
        digest.result(&mut output);
        digest.reset();

        // hash(MAC_write_secret + pad_2 + A);
        digest.input(write_secret);
        digest.input(&MD5_PAD_2);
        digest.input(&output);
        digest.result(&mut output);
        output
    }

    /// Computes a mac using the SHA1 hashing digest and padding for the
    /// provided message and details
    ///
    /// # Arguments
    /// * write_secret - The mac write secret
    /// * ty - The message type
    /// * message - The message payload
    /// * seq - The message sequence number
    fn compute_sha1(write_secret: &[u8], ty: u8, message: &[u8], seq: &u64) -> Sha1Hash {
        let mut output: Sha1Hash = [0u8; SHA1_HASH_LENGTH];
        let mut digest = Sha1::new();
        // A = hash(MAC_write_secret + pad_1 + seq_num + SSLCompressed.type + SSLCompressed.length + SSLCompressed.fragment)
        digest.input(write_secret);
        digest.input(&SHA1_PAD_1);
        digest.input(&seq.to_be_bytes());
        digest.input(&[ty]);
        let length = u16::to_be_bytes(message.len() as u16);
        digest.input(&length);
        digest.input(message);
        digest.result(&mut output);
        digest.reset();

        // hash(MAC_write_secret + pad_2 + A);
        digest.input(write_secret);
        digest.input(&SHA1_PAD_2);
        digest.input(&output);
        digest.result(&mut output);
        output
    }

    /// Validates the mac on the provided payload splitting the mac itself from
    /// the payload
    ///
    /// # Arguments
    /// * payload - The payload to validate
    /// * ty - The message type
    /// * seq - The message sequence
    pub fn validate(&self, payload: &mut Vec<u8>, ty: u8, seq: &u64) -> bool {
        match self {
            Self::Md5(write_secret) => {
                let mac = payload.split_off(payload.len() - 16);
                let computed = Self::compute_md5(write_secret, ty, payload, seq);
                mac.eq(&computed)
            }
            Self::Sha1(write_secret) => {
                let mac = payload.split_off(payload.len() - 20);
                let computed = Self::compute_sha1(write_secret, ty, payload, seq);
                mac.eq(&computed)
            }
        }
    }

    /// Computes the mac for a message that is going to be send and appends
    /// the payload to the message
    ///
    /// # Arguments
    /// * payload - The message payload
    /// * ty - The message type
    /// * seq - The message sequence
    pub fn append(&self, payload: &mut Vec<u8>, ty: u8, seq: &u64) {
        match self {
            Self::Md5(write_secret) => {
                let computed = Self::compute_md5(write_secret, ty, payload, seq);
                payload.extend_from_slice(&computed);
            }
            Self::Sha1(write_secret) => {
                let computed = Self::compute_sha1(write_secret, ty, payload, seq);
                payload.extend_from_slice(&computed);
            }
        }
    }
}

/// Structure for keys and mac generators derived from
/// the key block
pub struct Keys {
    /// The master key derived from the pre master key
    pub master_key: MasterKey,
    /// Mac generator for generic mac hashes for the server
    pub client_mac: MacGenerator,
    /// Mac generator for generic mac hashes for the client
    pub server_mac: MacGenerator,
    /// Client RC4 key
    pub client_key: Rc4,
    /// Server RC4 key
    pub server_key: Rc4,
}

/// Creates the key by creating a key block using the provided pre master key
/// and randoms using the hash length of the provided hashing algorithm
///
/// # Arguments
/// * pm_key - The pre master key
/// * cr - The client random
/// * sr - The server random
/// * alg - The hashing algorithm to use
pub fn create_keys(pm_key: &[u8], cr: SSLRandom, sr: SSLRandom, alg: HashAlgorithm) -> Keys {
    // Generate master key
    let mut master_key: MasterKey = [0u8; 48];
    generate_key_block(&mut master_key, pm_key, &cr.0, &sr.0);

    // Generate key block 80 bytes long (20x2 for write secrets + 16x2 for write keys) only 72 bytes used
    let mut key_block = [0u8; 80];
    generate_key_block(&mut key_block, &master_key, &sr.0, &cr.0);

    // Split the mac values from the key block
    let (client_mac, key_block) = MacGenerator::split_key_block(&alg, &key_block);
    let (server_mac, key_block) = MacGenerator::split_key_block(&alg, key_block);

    let client_key: Rc4 = Rc4::new(&key_block[0..16]);
    let server_key: Rc4 = Rc4::new(&key_block[16..32]);

    Keys {
        master_key,
        client_mac,
        server_mac,
        client_key,
        server_key,
    }
}

/// Generates a key block storing it in the provided output slice using the provided
/// key and random values
///
/// # Arguments
/// * out - The output slice to store the key block in
/// * key - The key to use
/// * rand_1 - The first random to use
/// * rand_2 - The second rando to use
fn generate_key_block(out: &mut [u8], key: &[u8], rand_1: &RandomInner, rand_2: &RandomInner) {
    // The digest use for the outer hash
    let mut outer = Md5::new();

    // The digest used for the inner hash
    let mut inner = Sha1::new();
    // Storage for the inner bytes
    let mut inner_value = [0u8; 20];

    let mut i = 1; // Number of salt chars to include (Increased every round)
    let mut salt_byte = b'A'; // Byte value of the salt char

    for chunk in out.chunks_mut(16) {
        // Feed salt bytes into hash
        for _ in 0..i {
            inner.input(&[salt_byte])
        }

        inner.input(key);
        inner.input(rand_1);
        inner.input(rand_2);
        inner.result(&mut inner_value);
        inner.reset();

        outer.input(key);
        outer.input(&inner_value);
        outer.result(chunk);
        outer.reset();

        // A -> B -> C -> D -> E
        salt_byte += 1;
        // A -> BB -> CCC -> DDD -> EEEE
        i += 1;
    }
}

/// Computes the finished message hashes for the provided transcript,
/// secret and sender
///
/// `master_secret` The session master secret
/// `is_client`     Whther to compute using the client value or server value
/// `transcript`    The transcript to compute hashes with
pub fn compute_finished_hashes(
    master_secret: &[u8],
    is_client: bool,
    transcript: &[u8],
) -> (Md5Hash, Sha1Hash) {
    let sender_value: u32 = if is_client { 0x434C4E54 } else { 0x53525652 };
    let sender_value: [u8; 4] = sender_value.to_be_bytes();
    let md5_hash: Md5Hash = compute_finished_md5(master_secret, &sender_value, transcript);
    let sha1_hash: Sha1Hash = compute_finished_sha1(master_secret, &sender_value, transcript);
    (md5_hash, sha1_hash)
}

/// Computes a finished hash value using MD5 for the
/// provided transcript using the sender value and
/// master secret
///
/// # Arguments
/// * master_secret - The master secret value
/// * sender_value - The sender value
/// * transcript - The transcript to hash
fn compute_finished_md5(
    master_secret: &[u8],
    sender_value: &[u8; 4],
    transcript: &[u8],
) -> Md5Hash {
    let mut output: Md5Hash = [0u8; MD5_HASH_LENGTH];
    let mut digest = Md5::new();

    digest.input(transcript);
    digest.input(sender_value);
    digest.input(master_secret);
    digest.input(&MD5_PAD_1);
    digest.result(&mut output);
    digest.reset();

    digest.input(master_secret);
    digest.input(&MD5_PAD_2);
    digest.input(&output);
    digest.result(&mut output);

    output
}

/// Computes a finished hash value using SHA1 for the
/// provided transcript using the sender value and
/// master secret
///
/// # Arguments
/// * master_secret - The master secret value
/// * sender_value - The sender value
/// * transcript - The transcript to hash
fn compute_finished_sha1(
    master_secret: &[u8],
    sender_value: &[u8; 4],
    transcript: &[u8],
) -> Sha1Hash {
    let mut output: Sha1Hash = [0u8; SHA1_HASH_LENGTH];
    let mut digest = Sha1::new();

    digest.input(transcript);
    digest.input(sender_value);
    digest.input(master_secret);
    digest.input(&SHA1_PAD_1);
    digest.result(&mut output);
    digest.reset();

    digest.input(master_secret);
    digest.input(&SHA1_PAD_2);
    digest.input(&output);
    digest.result(&mut output);

    output
}
