//! Module containing decryptor and encryptor implementations for
//! messages using RC4

use crate::{
    crypto::MacGenerator,
    msg::{BorrowedMessage, Message, OpaqueMessage},
};
use crypto::{rc4::Rc4, symmetriccipher::SynchronousStreamCipher};

/// Encryptor wrapper for encrypting borrwoed messages and returning an
/// opaque message with a mac appended and the contents encryted
pub struct Rc4Encryptor {
    /// The encryption key
    key: Rc4,
    /// The mac generator
    mac: MacGenerator,
    /// The current sequence number
    seq: u64,
}

impl Rc4Encryptor {
    /// Creates a new RC4 encryptor from the provided key bytes and
    /// the provided mac generator
    ///
    /// `key` The RC4 key bytes
    /// `mac` The mac generator
    pub fn new(key: Rc4, mac: MacGenerator) -> Self {
        Self { key, mac, seq: 0 }
    }
}

impl Rc4Encryptor {
    /// Encrypts the provided message appending the mac address
    /// to the message and increasing the sequence number
    pub fn encrypt(&mut self, message: BorrowedMessage) -> OpaqueMessage {
        let mut payload = message.payload.to_vec();
        self.mac
            .append(&mut payload, message.message_type.value(), &self.seq);

        let mut payload_enc = vec![0u8; payload.len()];
        self.key.process(&payload, &mut payload_enc);
        self.seq += 1;
        OpaqueMessage {
            message_type: message.message_type,
            payload: payload_enc,
        }
    }
}

/// Decryptor wrapper for decrypting opaque messages and returning a
/// message with the mac removed and the contents decrypted
pub struct Rc4Decryptor {
    /// The decryption key
    key: Rc4,
    /// The mac generator
    mac: MacGenerator,
    /// The current sequence number
    seq: u64,
}

impl Rc4Decryptor {
    /// Creates a new RC4 decryptor from the provided key bytes and
    /// the provided mac generator
    ///
    /// `key` The RC4 key bytes
    /// `mac` The mac generator
    pub fn new(key: Rc4, mac: MacGenerator) -> Self {
        Self { key, mac, seq: 0 }
    }
}

/// Error type for invalid mac hashes on a decrypted
/// message.
pub struct InvalidMacHash;

impl Rc4Decryptor {
    /// Decrypts the provided message removing and validating the mac address
    /// of the message and increasing the sequence number. Will return
    /// a
    pub fn decrypt(&mut self, message: OpaqueMessage) -> Result<Message, InvalidMacHash> {
        let mut payload = vec![0u8; message.payload.len()];
        self.key.process(&message.payload, &mut payload);

        if !self
            .mac
            .validate(&mut payload, message.message_type.value(), &self.seq)
        {
            return Err(InvalidMacHash);
        }

        self.seq += 1;

        Ok(Message {
            message_type: message.message_type,
            payload,
        })
    }
}
