//! Structures for storing server information

pub use super::msg::types::Certificate;
pub use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};

/// Stores the private key and chain of certificates used by
/// the server when communicating with clients
pub struct BlazeServerData {
    /// The server private key
    pub private_key: RsaPrivateKey,
    /// Chain of server certificates proceeding sequentially upward
    pub certificate_chain: Vec<Certificate>,
}

impl BlazeServerData {
    /// Creates a new [BlazeServerData] from the provided `private_key` and
    /// `certificate chain`.
    ///
    /// Will panic if the provided `certificate_chain` is empty
    pub fn new(private_key: RsaPrivateKey, certificate_chain: Vec<Certificate>) -> Self {
        if certificate_chain.is_empty() {
            panic!("Empty server certificate chain");
        }

        Self {
            private_key,
            certificate_chain,
        }
    }
}

impl Default for BlazeServerData {
    fn default() -> Self {
        // Load the included private key
        let private_key = {
            let key_pem = include_str!("server.key");
            RsaPrivateKey::from_pkcs8_pem(key_pem).expect("Failed to load private key")
        };
        // Load the included certificate chain
        let certificate_chain: Vec<Certificate> =
            vec![Certificate::from_static(include_bytes!("server.crt"))];

        Self {
            private_key,
            certificate_chain,
        }
    }
}
