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
