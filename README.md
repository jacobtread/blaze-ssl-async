# ⚙️Blaze SSL Async

![License](https://img.shields.io/github/license/jacobtread/blaze-ssl-async?style=for-the-badge)
![Cargo Version](https://img.shields.io/crates/v/blaze-ssl-async?style=for-the-badge)
![Cargo Downloads](https://img.shields.io/crates/d/blaze-ssl-async?style=for-the-badge)


> 📌**IMPORTANT**📌 If you're here looking for a security focused SSL library this is not it check out
> [rustls (https://github.com/rustls/rustls)](https://github.com/rustls/rustls) This 
> library exists to fill a legacy need for EA games that depend upon the 
> gosredirector.ea.com service

This is the async implementation of Blaze-SSL (Using tokio) if you would like a sync version you can
find that [Here](https://github.com/jacobtread/blaze-ssl) 

## ❔ What

**BlazeSSL Async** is an implementation of the SSLv3 protocol and the TLS_RSA_WITH_RC4_128_SHA, and TLS_RSA_WITH_RC4_128_MD5 ciphers. This library does not implement the entirety of the protocol it only implements client auth through x509 certificates and server auth through the self signed key.pem and cert.pem stored in the src directory. This is used by the [Pocket Relay](https://github.com/PocketRelay) project to allow the server to accept connections that would normally go to gosredirector.ea.com and also connect to the official servers for both MITM logic and Origin authentication.

## 📄 Usage

Add dependency to your cargo dependencies

```toml
blaze-ssl-async = "^0.3"
```

### Connecting to a server

The example below if for connecting to a server as a client

```rust
// BlazeStream is a wrapper over tokios TcpStream
use blaze_ssl_async::stream::BlazeStream;

// Tokio read write extensions used for read_exact and write_all
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// BlazeStream::connect takes in any value that implements ToSocketAddrs
// some common implementations are "HOST:PORT" and ("HOST", PORT)
let mut stream = BlazeStream::connect(("159.153.64.175", 42127))
    .await
    .expect("Failed to create blaze stream");

// TODO... Read from the stream as you would a normal TcpStream
let mut buf = [0u8; 12];
stream.read_exact(&mut buf)
    .await
    .expect("Failed to read 12 bytes");
// Write the bytes back
stream.write_all(&buf)
    .await
    .expect("Failed to write 12 by tes");
// You **MUST** flush BlazeSSL streams or else the data will never
// be sent to the client
stream.flush()
    .await
    .expect("Failed to flush");
```

### Binding a server

The example below is an example for creating a server that accepts clients

```rust
// BlazeListener is wrapper over tokios TcpListener
use crate::stream::BlazeListener;

// Tokio read write extensions used for read_exact and write_all
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Bind a listener accepts the same address values as the tokio TcpListener
let listener = BlazeListener::bind(("0.0.0.0", 42127))
        .await
        .expect("Failed to bind blaze listener");

// Accept new connections
loop {
    // Accept the initial TcpStream without SSL 
    let (stream, _) = listener
        .accept()
        .await
        .expect("Failed to accept stream");
    tokio::spawn(async move {
        // Complete the SSL handshake process in a spawned task
        let stream = stream.finish_accept()
            .await
            .expect("Failed to finish accepting stream");

        // Read and write to the stream the same as in the client example
    });
}
```

> Note: This `accept` and `finish_accept` system is in place as to not prevent accepting new connections while a handshake is being completed. If you want
> to block new connections and do the handshaking portion in the accept you can
> use `blocking_accept` instead of `accept` and the `finish_accept` call is no longer necessary 


## ❔ Why 

This SSL implementation is to provide the bare minimum SSL implementation required for the
initial redirect portion of the Mass Effect 3 multiplayer protocol when the client reaches 
out to gosredirector.ea.com. The client refuses to use any other protocols or cipher suites 
and in order to use SSLv3 and these cipher suites you either have to modify Registry keys
(In the case of Schannel) or compile a custom version of OpenSSL; Which isn't very practical
or intuitive for emulating these servers.

## 🧾 License

The MIT License (MIT)

Copyright (c) 2022 Jacobtread

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