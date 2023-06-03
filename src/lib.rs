//! # Blaze SSL Async
//! **BlazeSSL Async** is an implementation of the SSLv3 protocol and the TLS_RSA_WITH_RC4_128_SHA,
//! and TLS_RSA_WITH_RC4_128_MD5 ciphers.
//!
//! This library does not implement the entirety of the protocol it only implements client auth through x509
//! certificates and server auth through the self signed key.pem and cert.pem stored in the src directory.
//!
//! This is used by the [Pocket Relay](https://github.com/PocketRelay) project to allow the server to accept connections
//! that would normally go to gosredirector.ea.com and also connect to the official servers for both MITM logic
//! and Origin authentication.
//!
//! ## Usage
//!
//! Add dependency to your cargo dependencies
//!
//! ```toml
//! blaze-ssl-async = "^0.3"
//! ```
//!
//! ### Connecting to a server
//!
//! The example below if for connecting to a server as a client
//!
//! ```rust
//! // BlazeStream is a wrapper over tokios TcpStream
//! use blaze_ssl_async::stream::BlazeStream;
//!
//! // Tokio read write extensions used for read_exact and write_all
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! // BlazeStream::connect takes in any value that implements ToSocketAddrs
//! // some common implementations are "HOST:PORT" and ("HOST", PORT)
//! let mut stream = BlazeStream::connect(("159.153.64.175", 42127))
//!     .await
//!     .expect("Failed to create blaze stream");
//!
//! // TODO... Read from the stream as you would a normal TcpStream
//! let mut buf = [0u8; 12];
//! stream.read_exact(&mut buf)
//!     .await
//!     .expect("Failed to read 12 bytes");
//! // Write the bytes back
//! stream.write_all(&buf)
//!     .await
//!     .expect("Failed to write 12 by tes");
//! // You **MUST** flush BlazeSSL streams or else the data will never
//! // be sent to the client
//! stream.flush()
//!     .await
//!     .expect("Failed to flush");
//! ```
//!
//! ### Binding a server
//!
//! The example below is an example for creating a server that accepts clients
//!
//! ```rust
//! // BlazeListener is wrapper over tokios TcpListener
//! use crate::stream::BlazeListener;
//!
//! // Tokio read write extensions used for read_exact and write_all
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//!
//! // Bind a listener accepts the same address values as the tokio TcpListener
//! let listener = BlazeListener::bind(("0.0.0.0", 42127))
//!         .await
//!         .expect("Failed to bind blaze listener");
//!
//! // Accept new connections
//! loop {
//!     // Accept the initial TcpStream without SSL
//!     let (stream, _) = listener
//!         .accept()
//!         .await
//!         .expect("Failed to accept stream");
//!     tokio::spawn(async move {
//!         // Complete the SSL handshake process in a spawned task
//!         let stream = stream.finish_accept()
//!             .await
//!             .expect("Failed to finish accepting stream");
//!
//!         // Read and write to the stream the same as in the client example
//!     });
//! }
//! ```
//!
//! > **Note**: This `accept` and `finish_accept` system is in place as to not prevent accepting new connections while a handshake is being completed. If you want
//! > to block new connections and do the handshaking portion in the accept you can
//! > use `blocking_accept` instead of `accept` and the `finish_accept` call is no longer necessary

mod crypto;
pub mod data;
mod handshake;
mod msg;

/// Module containing RC4 encryptor and decryptor logic
mod rc4;

/// Module containing stream related logic
pub mod stream;

/// Re-export all stream types
pub use stream::*;

#[cfg(test)]
mod test {
    use crate::stream::{BlazeListener, BlazeStream};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_server() {
        // Begin listening for connections
        let listener = BlazeListener::bind(("0.0.0.0", 42127))
            .await
            .expect("Failed to bind blaze listener");

        loop {
            let (stream, _) = listener
                .blocking_accept()
                .await
                .expect("Failed to accept stream");
            tokio::spawn(handle(stream));
        }
    }

    async fn handle(mut stream: BlazeStream) {
        let mut buf = [0u8; 20];
        loop {
            buf.fill(0);
            let read_count = stream.read(&mut buf).await.unwrap();
            if read_count > 0 {
                println!("{:?}", &buf[..read_count]);
            }
            sleep(Duration::from_secs(5)).await
        }
    }

    #[tokio::test]
    async fn test_client() {
        let addr = ("159.153.64.175", 42127);
        // old = 159.153.64.175;

        let mut stream = BlazeStream::connect(addr)
            .await
            .expect("Failed to create blaze stream");

        let test = [0u8; 12];
        stream.write_all(&test).await.expect("Failed to write");
        stream.flush().await.expect("Failed to flush");

        let mut buf = [0u8; 12];
        stream.read_exact(&mut buf).await.expect("Read bytes");

        println!("{:?} Bytes", buf)
    }
}
