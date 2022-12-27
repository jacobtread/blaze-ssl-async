use crate::msg::types::Certificate;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use std::sync::Arc;

pub struct BlazeServerData {
    /// The server private key
    pub private_key: RsaPrivateKey,
    /// The server certificate
    pub certificate: Arc<Certificate>,
}

impl Default for BlazeServerData {
    fn default() -> Self {
        let key_pem = include_str!("key.pem");
        let private_key =
            RsaPrivateKey::from_pkcs8_pem(key_pem).expect("Failed to load private key");
        let cert_pem = include_bytes!("cert.pem");
        let cert_bytes = pem_rfc7468::decode_vec(cert_pem)
            .expect("Unable to parse server certificate")
            .1;
        let certificate = Certificate(cert_bytes);
        Self {
            private_key,
            certificate: Arc::new(certificate),
        }
    }
}
