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
            let cert_pem = include_bytes!("cert.pem");
            let cert_bytes = pem_rfc7468::decode_vec(cert_pem)
                .expect("Unable to parse server certificate")
                .1;
            Arc::new(Certificate(cert_bytes))
        };
        Self {
            private_key,
            certificate,
        }
    }
}
