use super::msg::types::Certificate;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use std::sync::Arc;

/// Structure for storing the additional data for the server
/// implementation
pub struct BlazeServerData {
    /// The server private key
    pub private_key: RsaPrivateKey,
    /// The server certificate
    pub certificate: Arc<Certificate>,
}

impl Default for BlazeServerData {
    fn default() -> Self {
        // Load the included private key
        let private_key = {
            let key_pem = include_str!("key.pem");
            RsaPrivateKey::from_pkcs8_pem(key_pem).expect("Failed to load private key")
        };
        // Load the included certificate
        let certificate = {
            let cert_bytes = include_bytes!("cert.bin");
            Arc::new(Certificate(cert_bytes.to_vec()))
        };
        Self {
            private_key,
            certificate,
        }
    }
}
