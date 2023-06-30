//! Let's start with capturing inputs and outputs of a TLS stream
//! This is copied from the example of rustls/rustls
use rustls::{OwnedTrustAnchor, RootCertStore};
use std::io::{Read, Write, stdout};
use std::net::TcpStream;
use std::sync::Arc;

struct LoggedTcpStream<T> {
    writer: T,
    socket: TcpStream,
}

impl<T: Write> LoggedTcpStream<T> {
    fn new(writer: T, socket: TcpStream) -> Self {
        return Self { writer, socket };
    }
}

impl<T: Write> Read for LoggedTcpStream<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let nbytes = self.socket.read(buf)?;
        self.writer.write(buf)?;
        return Ok(nbytes);
    }
}

impl<T: Write> Write for LoggedTcpStream<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(&buf)?;
        return self.socket.write(&buf);
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

/// Convert bytes to hex-encoding, then write to the underlying writer
struct HexEncoder<T> {
    writer: T,
}

impl<T: Write> HexEncoder<T> {
    fn new(writer: T) -> Self {
        return Self { writer };
    }
}

impl<T: Write> Write for HexEncoder<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let hexstr = hex::encode(buf);
        self.writer.write(hexstr.as_bytes())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

fn main() {
    let mut root_store = RootCertStore::empty();
    root_store.add_server_trust_anchors(
        webpki_roots::TLS_SERVER_ROOTS
            .0
            .iter()
            .map(|ta| {
                OwnedTrustAnchor::from_subject_spki_name_constraints(
                    ta.subject,
                    ta.spki,
                    ta.name_constraints,
                )
            }),
    );
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = "www.rust-lang.org".try_into().unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = LoggedTcpStream::new(
        HexEncoder::new(stdout()),
        TcpStream::connect("www.rust-lang.org:443").unwrap()
    );

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    tls.write_all(
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: www.rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();
    let ciphersuite = tls
        .conn
        .negotiated_cipher_suite()
        .unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    // stdout().write_all(&plaintext).unwrap();
}
