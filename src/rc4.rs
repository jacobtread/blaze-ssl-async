//! Module containing decryptor and encryptor implementations for
//! messages using RC4 along with an RC4 in place implementation

use super::{
    crypto::MacGenerator,
    msg::{BorrowedMessage, Message},
};

/// RC4 implementation
pub struct Rc4 {
    i: u8,
    j: u8,
    state: [u8; 256],
}

impl Rc4 {
    /// Creates a new RC4 struct from the provided key bytes.
    ///
    /// `key` The key that should be used
    pub fn new(key: &[u8]) -> Self {
        let mut state: [u8; 256] = [0u8; 256];

        for (i, x) in state.iter_mut().enumerate() {
            *x = i as u8;
        }

        let mut j: u8 = 0;
        for i in 0..256 {
            j = j.wrapping_add(state[i]).wrapping_add(key[i % key.len()]);
            state.swap(i, j as usize);
        }

        Rc4 { i: 0, j: 0, state }
    }

    /// Retrieves the next value to use for RC4
    fn next(&mut self) -> u8 {
        self.i = self.i.wrapping_add(1);
        self.j = self.j.wrapping_add(self.state[self.i as usize]);
        self.state.swap(self.i as usize, self.j as usize);
        self.state[(self.state[self.i as usize].wrapping_add(self.state[self.j as usize])) as usize]
    }

    /// Processes the provided input in place directly modifying it
    ///
    /// `input` The input to process
    fn process(&mut self, input: &mut [u8]) {
        for value in input {
            *value ^= self.next();
        }
    }
}

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
    pub fn encrypt(&mut self, message: BorrowedMessage) -> Message {
        let mut payload = message.payload.to_vec();
        self.mac
            .append(&mut payload, message.message_type.value(), &self.seq);
        self.key.process(&mut payload);
        self.seq += 1;
        Message {
            message_type: message.message_type,
            payload,
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

impl Rc4Decryptor {
    /// Decrypts the provided message removing and validating the mac address
    /// of the message and increasing the sequence number. Decryption is done
    /// in place and will return true if the mac matches or false if it doesn't
    pub fn decrypt(&mut self, message: &mut Message) -> bool {
        self.key.process(&mut message.payload);
        if !self.mac.validate(
            &mut message.payload,
            message.message_type.value(),
            &self.seq,
        ) {
            return false;
        }
        self.seq += 1;
        true
    }
}
