# ⚙️Blaze SSL Async

![License](https://img.shields.io/github/license/jacobtread/blaze-ssl-async?style=for-the-badge)
![Cargo Version](https://img.shields.io/crates/v/blaze-ssl-async?style=for-the-badge)
![Cargo Downloads](https://img.shields.io/crates/d/blaze-ssl-async?style=for-the-badge)

This is a *minimal* implementation of the SSLv3 protocol. It supports only the `TLS_RSA_WITH_RC4_128_SHA` and `TLS_RSA_WITH_RC4_128_MD5` ciphers. It does not implement all SSLv3 features

This is used by [Pocket Relay](https://github.com/PocketRelay/) for locally handling game connections from Mass Effect 3 which use a home grown SSLv3 implementaton by EA and as such cannot use any other newer protocol.

## 📌 Important note

This is *not* intended to be a secure SSL implementation. This is intended for legacy games and other software where it is not possible to use a more secure protocol.

If you are looking for a security focus SSL implementation you should instead check out https://github.com/rustls/rustls or https://github.com/sfackler/rust-native-tls

This implementation was designed specifically for [Pocket Relay](https://github.com/PocketRelay/) for use with Mass Effect 3.

It does not support any of the following features:
- Session resumption
- Client certificate authentication
- Server certificate verification (Trusts all server certificates)
- Server key exchange
- Recovering from warning alerts (All warnings are treated as fatal)
- SSL Compression modes

## 📄 Usage

Add dependency to your cargo dependencies

```toml
blaze-ssl-async = "^0.3"
```

### Crate Features

The default features are `["blaze-cert"]`

| Feature        | Description                                                                                                                              |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| **blaze-cert** | Includes a built in default BlazeServerContext that uses a certificate built to bypass verification of older EA ProtoSSL implementations |


### Connecting to a server

The example below if for connecting to a server as a client

```rust,no_run
// BlazeStream is a wrapper over tokio TcpStream
use blaze_ssl_async::BlazeStream;

// Tokio read write extensions used for read_exact and write_all
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    // BlazeStream::connect takes in any value that implements ToSocketAddrs
    // some common implementations are "HOST:PORT" and ("HOST", PORT)
    let mut stream = BlazeStream::connect(("159.153.64.175", 42127)).await?;

    // TODO... Read from the stream as you would a normal TcpStream
    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf).await?;
    // Write the bytes back
    stream.write_all(&buf).await?;
    // You **MUST** flush BlazeSSL streams or else the data will never
    // be sent to the client (Attempt to read will automatically flush)
    stream.flush().await?;

    Ok(())
}
```

### Binding a server

The example below is an example for creating a server that accepts clients

```rust,no_run
// BlazeListener is wrapper over tokios TcpListener
use blaze_ssl_async::{BlazeListener, BlazeServerContext};
// Tokio read write extensions used for read_exact and write_all
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let context: Arc<BlazeServerContext> = Default::default(); 
    // Bind a listener accepts the same address values as the tokio TcpListener
    let listener = BlazeListener::bind(("0.0.0.0", 42127), context).await?;

    // Accept new connections
    loop {
        // Accept the initial TcpStream without SSL 
        let accept = listener.accept().await?;
        tokio::spawn(async move {
            // Complete the SSL handshake process in a spawned task
            let (stream, addr) = accept.finish_accept()
                .await
                .expect("Failed to finish accepting stream");

            // Read and write to the stream the same as in the client example
        });
    }
}
```

## 🧾 License

The MIT License (MIT)

Copyright (c) 2022 - 2023 Jacobtread

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.