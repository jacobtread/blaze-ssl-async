//! Test for connecting the client portion to the server portion
//! and transmitting information

use blaze_ssl_async::{BlazeListener, BlazeStream};
use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

/// Testing harness for creating a SSL server that can
/// be connected to
struct ServerTestHarness {
    pub addr: SocketAddr,
    join_handle: JoinHandle<()>,
}

impl ServerTestHarness {
    async fn new<H, F>(handler: H) -> Self
    where
        H: FnOnce(BlazeStream) -> F + Clone + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        let listener = BlazeListener::bind((Ipv4Addr::LOCALHOST, 0), Default::default())
            .await
            .expect("Failed to bind socket");
        let addr = listener
            .local_addr()
            .expect("Failed to determine bound address");

        println!("Test harness running on: {addr}");

        let abort_handle = tokio::spawn(async move {
            loop {
                let handler = handler.clone();
                let (stream, _) = listener.blocking_accept().await.unwrap();
                handler(stream).await;
            }
        });

        Self {
            addr,
            join_handle: abort_handle,
        }
    }
}

impl Drop for ServerTestHarness {
    fn drop(&mut self) {
        self.join_handle.abort();
    }
}

/// Tests a connection between a SSL client and SSL server by connecting
/// to the server which will send "Hello World", that the client expects
/// back
#[tokio::test]
async fn test_hello_world() {
    const MESSAGE: &[u8; 11] = b"Hello world";

    // Start a new test harness server
    let harness = ServerTestHarness::new(|mut stream| async move {
        // Write the test message
        stream.write_all(MESSAGE).await.unwrap();
        stream.flush().await.unwrap();
    })
    .await;

    // Connect to the test harness server
    let mut stream = BlazeStream::connect(harness.addr).await.unwrap();

    // Read the response from the server
    let mut buffer = [0u8; MESSAGE.len()];
    stream.read_exact(&mut buffer).await.unwrap();

    // Ensure it matches the request
    assert_eq!(&buffer, MESSAGE);
}
