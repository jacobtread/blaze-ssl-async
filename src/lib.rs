pub(crate) mod crypto;
pub(crate) mod handshake;
pub(crate) mod msg;
pub mod stream;

#[cfg(test)]
mod test {
    use crate::stream::{BlazeStream, StreamMode};
    use std::net::TcpListener;
    use std::thread;
    use std::thread::sleep;
    use std::time::Duration;
    use std::{io::Read, net::TcpStream};

    #[test]
    fn test_server() {
        // Begin listening for connections
        let listener = TcpListener::bind(("0.0.0.0", 42127)).expect("Failed to bind TCP listener");

        for stream in listener.incoming() {
            thread::spawn(move || {
                let stream = stream.expect("Failed to accept stream");
                let stream = &mut BlazeStream::new(stream, StreamMode::Server)
                    .expect("Failed to complete handshake");
                let mut buf = [0u8; 20];
                loop {
                    buf.fill(0);
                    let read_count = stream.read(&mut buf).unwrap();
                    if read_count > 0 {
                        println!("{:?}", &buf[..read_count]);
                    }
                    sleep(Duration::from_secs(5))
                }
            });
        }
    }

    #[test]
    fn test_client() {
        let addr = ("gsprodblapp-02.ea.com", 10025);
        // old = 159.153.64.175;
        let stream = TcpStream::connect(addr).expect("Unable to connect to server");
        let stream =
            &mut BlazeStream::new(stream, StreamMode::Client).expect("Failed SSL handshake");
    }
}
