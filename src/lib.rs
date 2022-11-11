pub(crate) mod crypto;
pub(crate) mod handshake;
pub(crate) mod msg;
pub mod stream;

#[cfg(test)]
mod test {
    use crate::stream::{BlazeStream, StreamMode};
    use std::time::Duration;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_server() {
        // Begin listening for connections
        let listener = TcpListener::bind(("0.0.0.0", 42127))
            .await
            .expect("Failed to bind TCP listener");

        loop {
            let (stream, _) = listener.accept().await.expect("Failed to accept stream");
            let stream = stream;
            let stream = BlazeStream::new(stream, StreamMode::Server)
                .await
                .expect("Failed to complete handshake");
            tokio::spawn(handle(stream));
        }
    }

    async fn handle(mut stream: BlazeStream<TcpStream>) {
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
        let addr = ("gsprodblapp-02.ea.com", 10025);
        // old = 159.153.64.175;
        let stream = TcpStream::connect(addr)
            .await
            .expect("Unable to connect to server");
        let stream = &mut BlazeStream::new(stream, StreamMode::Client)
            .await
            .expect("Failed SSL handshake");

        let mut buf = [0u8; 20];
        stream.read_exact(&mut buf).await.expect("Read bytes");
    }
}
