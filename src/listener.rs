//! SSL server listener, replacement for [TcpListener] that can
//! accept SSL connections.
//!
//! ```rust,no_run
//! // BlazeListener is wrapper over tokios TcpListener
//! use blaze_ssl_async::{BlazeListener, BlazeServerContext};
//! // Tokio read write extensions used for read_exact and write_all
//! use tokio::io::{AsyncReadExt, AsyncWriteExt};
//! use std::sync::Arc;
//!
//! #[tokio::main]
//! async fn main() -> std::io::Result<()> {
//!     let context: Arc<BlazeServerContext> = Default::default();
//!     // Bind a listener accepts the same address values as the tokio TcpListener
//!     let listener = BlazeListener::bind(("0.0.0.0", 42127), context).await?;
//!
//!     // Accept new connections
//!     loop {
//!         // Accept the initial TcpStream without SSL
//!         let accept = listener.accept().await?;
//!         tokio::spawn(async move {
//!             // Complete the SSL handshake process in a spawned task
//!             let (stream, addr) = accept.finish_accept()
//!                 .await
//!                 .expect("Failed to finish accepting stream");
//!
//!             // Read and write to the stream the same as in the client example
//!         });
//!     }
//! }
//! ```

pub use super::msg::types::Certificate;
use crate::stream::BlazeStream;
pub use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use std::{
    net::SocketAddr,
    sync::Arc,
    task::{ready, Context, Poll},
};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

/// Listener wrapping TcpListener in order to accept
/// SSL connections
pub struct BlazeListener {
    /// The underlying TcpListener
    listener: TcpListener,
    /// Shared context for the listener connections
    context: Arc<BlazeServerContext>,
}

/// Context state for a SSL server, contains the private
/// key and certificate chain
pub struct BlazeServerContext {
    /// The server private key
    pub private_key: RsaPrivateKey,
    /// Collection of server certificates, starting with the server
    /// certificate followed by any certificate authority certificates
    /// preceeding sequentually upward.
    pub certificate_chain: Vec<Certificate>,
}

impl BlazeServerContext {
    /// Creates a new [BlazeServerContext] from the provided `private_key` and
    /// `certificate chain`.
    ///
    /// Will panic if the provided `certificate_chain` is empty
    pub fn new(private_key: RsaPrivateKey, certificate_chain: Vec<Certificate>) -> Self {
        assert!(
            !certificate_chain.is_empty(),
            "Empty server certificate chain"
        );

        Self {
            private_key,
            certificate_chain,
        }
    }
}

/// Default [BlazeServerContext] using the built-in `server.key` and `server.crt`
/// which can be used to bypass certificate verification on older versions of
/// EA ProtoSSL
#[cfg(feature = "blaze-cert")]
impl Default for BlazeServerContext {
    fn default() -> Self {
        // Load the included private key
        let private_key = RsaPrivateKey::from_pkcs8_pem(include_str!("server.key"))
            .expect("Failed to load private key");

        // Load the included certificate chain
        let certificate_chain: Vec<Certificate> =
            vec![Certificate::from_static(include_bytes!("server.crt"))];

        Self {
            private_key,
            certificate_chain,
        }
    }
}

impl BlazeListener {
    /// Binds a new TcpListener wrapping it in a BlazeListener if no
    /// errors occurred
    ///
    /// ## Arguments
    /// * `addr`    - The addr(s) to attempt to bind on
    /// * `context` - The server context to use
    pub async fn bind<A: ToSocketAddrs>(
        addr: A,
        context: Arc<BlazeServerContext>,
    ) -> std::io::Result<BlazeListener> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self::from_tokio(listener, context))
    }

    /// Polls accepting a connection from the underlying listener.
    ///
    /// This function does *not* complete the SSL handshake, instead it
    /// gives you a [BlazeAccept] and you can use [BlazeAccept::finish_accept]
    /// to complete the handshake
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<std::io::Result<BlazeAccept>> {
        let (stream, addr) = ready!(self.listener.poll_accept(cx))?;
        Poll::Ready(Ok(BlazeAccept {
            stream,
            addr,
            context: self.context.clone(),
        }))
    }

    /// Accepts a new TcpStream from the underlying listener wrapping
    /// it in a server BlazeStream returning the wrapped stream and the
    /// stream addr.
    ///
    /// Awaiting the blaze stream creation here would mean connections
    /// wouldnt be able to be accepted so instead a BlazeAccept is returned
    /// and `finish_accept` should be called within a spawned task otherwise
    /// you can use `blocking_accept` to do an immediate handle
    pub async fn accept(&self) -> std::io::Result<BlazeAccept> {
        let (stream, addr) = self.listener.accept().await?;
        Ok(BlazeAccept {
            stream,
            addr,
            context: self.context.clone(),
        })
    }

    /// Accepts a new [BlazeStream] while blocking new connections until the
    /// SSL handshake is complete.
    ///
    /// This will prevent new connections from completing so its recommened
    /// you use [BlazeListener::accept] instead which allows you to defer
    /// the handshaking proccess.
    pub async fn blocking_accept(&self) -> std::io::Result<(BlazeStream, SocketAddr)> {
        let (stream, addr) = self.listener.accept().await?;
        let stream = BlazeStream::accept(stream, self.context.clone()).await?;
        Ok((stream, addr))
    }

    /// Replaces the server context with a new context
    pub fn set_context(&mut self, context: Arc<BlazeServerContext>) {
        self.context = context;
    }

    /// Creates a [BlazeListener] from an existing [TcpListener] and the
    /// provided `context`
    #[inline]
    pub fn from_tokio(listener: TcpListener, context: Arc<BlazeServerContext>) -> Self {
        Self { listener, context }
    }

    /// Creates a [BlazeListener] from an existing std [TcpListener] and the
    /// provided `context`
    pub fn from_std(
        listener: std::net::TcpListener,
        context: Arc<BlazeServerContext>,
    ) -> std::io::Result<Self> {
        let listener = TcpListener::from_std(listener)?;
        Ok(Self::from_tokio(listener, context))
    }

    /// Obtains the local address that the underlying listener is
    /// bound to
    #[inline]
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Consumes this listener returning the underlying [TcpListener]
    pub fn into_inner(self) -> TcpListener {
        self.listener
    }
}

/// Represents an stream accepting from a [BlazeListener] that
/// has not yet completed its SSL handshake.
///
/// To complete the handshake and get a [BlazeStream] call the
/// [BlazeAccept::finish_accept] function
pub struct BlazeAccept {
    /// The underlying stream
    stream: TcpStream,
    /// The socket address to the stream
    addr: SocketAddr,
    /// The server context to accept with
    context: Arc<BlazeServerContext>,
}

impl BlazeAccept {
    /// Completes the SSL handshake for this accepting connection turning it
    /// into a [BlazeStream] so that it can be used
    pub async fn finish_accept(self) -> std::io::Result<(BlazeStream, SocketAddr)> {
        BlazeStream::accept(self.stream, self.context)
            .await
            .map(|stream| (stream, self.addr))
    }
}
