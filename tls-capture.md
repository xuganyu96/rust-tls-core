# TLS Capture
One thing that I found useful for learning more about TLS is to watch how other TLS library does what it does, so I wrote a wrapper around Rust's `std::net::TcpStream` to capture the bytes that are sent and received, with the TLS client code copied from the simple client in `rustls/rustls`.

```rust
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
        let hexstr = hex::encode(&buf);
        writeln!(self.writer, "Received: {}", hexstr)?;
        return Ok(nbytes);
    }
}

impl<T: Write> Write for LoggedTcpStream<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let hexstr = hex::encode(&buf);
        writeln!(self.writer, "Sent: {}", hexstr)?;
        return self.socket.write(&buf);
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
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
        stdout(),
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
```

The capture is written [here](./tls-capture.log).

## The Client Hello?
This is the hexadecimal encoding of the first message, which was sent by the client and is presumably the ClientHello.

```
16030100f3010000ef03030c1968ab2bbd60205f2a40c7f0d492168535d0298c37d998e5eb01e55b61021e20135f1cec7cd5321636bd64411984fd58603bf896d1ef53820869160c6b068a840014130213011303c02cc02bcca9c030c02fcca800ff01000092002b00050403040303000b00020100000a00080006001d00170018000d00140012050304030807080608050804060105010401001700000005000501000000000000001600140000117777772e727573742d6c616e672e6f726700120000003300260024001d0020a04d556163020ff655beeacccf1bbc39c1acdf781551caec45e0e145b7995757002d0002010100230000
```

Before we break it down, let's first review the layers of abstraction.

The first layer of is the record layer, where the data is structured as follows:

```rust
struct TLSPlaintext {
    content_type: ContentType,
    legacy_protocol_version: ProtocolVersion,
    length: u16,
    fragment: Vec<u8>,
}
```

Then, `fragment` is structured with the second layer of abstraction:

```rust
struct HandshakeMessage {
    msg_type: HandshakeType,
    length: u24,
    payload: HandshakeMessagePayload,
}
```

The payload in this case is a `ClientHello`:

```rust
struct ClientHello {
    legacy_version: ProtocolVersion,
    random: Random,  // fixed-length vector
    legacy_session: [u8; 32],  // variable-length vector
    cipher_suites: Vec<CipherSuite>,  // variable-length vector,
    legacy_compression_method: [u8],  // variable-length vector
    extensions: Vec<Extension>, // variable-length
}
```

Since there are a variety of extensions, we will not cover all of them at once; instead, we will read through them one at a time when deconstructing the client hello message.

## Deconstructing the client hello
Let's start with the "header" of the record, which overs the first five bytes `0x16030100f3`:

```
0x16    => ContentType::Handshake
0x0301  => TLS v1.0, but only for compatibility reason
0x00f3  => the remainer of the message has 243 bytes
```

Then we have "header" for the handshake message, which contains four bytes `0x010000ef`:

```
0x01      => HandshakeType::ClientHello
0x0000ef  => the remainder of the message has 239 bytes; this checks out with the length above since
             the header took up 4 of the 243 bytes
```

The header of the client hello takes up the next X bytes:

```
0x0303
=> TLS v1.2 (2)

0x0c1968ab2bbd60205f2a40c7f0d492168535d0298c37d998e5eb01e55b61021e
=> 32 random bytes. Since "random" is a fixed length vector there is no need to encode the length

0x20 35f1cec7cd5321636bd64411984fd58603bf896d1ef53820869160c6b068a84
=> first, the length is encoded in 1 byte, indicating the session id to have 0x20 bytes (32 bytes)
=> then the actual legacy session ID

0x0014 1302 1301 1303 c02c c02b cca9 c030 c02f cca8 00ff
=> first, the cipher suite vector takes 0x0014 bytes (20 bytes)
=> then we have the following cipher suites encoded:
    0x1302: TLS_AES_256_GCM_SHA384
    0x1301: TLS_AES_128_GCM_SHA256
    0x1303: TLS_CHACHA20_POLY1305_SHA256
    0xc02c: ???
    0xc02b: ???
    0xcca9: ???
    0xc030: ???
    0xc02f: ???
    0xcca8: ???
    0x00ff: ???

0x0100:
=> legacy compression method, which, is set to a single elemt of 0x00 (null) in TLS V1.3
```

The remainder of the message is the variable-length vector that encodes the set of extensions. This variable length vector can have up to $2^{16} - 1$ bytes, so the first two bytes are used to encode the length `0x92`

```
0x0092
=> length of the extension vector
```

Before we deconstruct the extensions, let's review the struct of each extension:

```rust
struct Extension {
    extension_type: ExtensionType,  // 2 bytes each
    extension_data: Vec<u8>, // variable length with up to 2^16 - 1 bytes
}
```

Each extension is serialized using the `tag || length || content` format, where each tag is encoded with 2 bytes, and the length is encoded with 2 bytes, as well. With this, we know that the first extension has a tag value of `0x002b` and a length of `0x0005`:

```
0x002b, 0x0005
=> extension "supported_versions", content has 5 bytes
```

In the client version of the `supported_versions` extension, the content is a variable-length vector up to 254 bytes, meaning that the length of the vector is encoded in 1 byte:

```
0x04, 0x0304, 0x0303
=>  the content of the "supported_version" extension take up 4 bytes
=>  0x0304 encodes to TLS v1.3
    0x0303 encodes to TLS v1.2
```

The next extension's tag and length are `0x000b` and `0x0002`

```
tag: 0x000b
length: 0x0002
=> not sure what it is...

content: 0x0100
```

```
tag: 0x000a
length: 0x0008
=> supported_groups

content: 0x0006001d00170018
=> 0x0006 encodes the length of the variable-length vector "named_group_list"
=> 0x001d encodes "x25519"
   0x0017 encodes "secp256r1"
   0x0018 encodes "secp384r1"
   all three are in the elliptic curve groups
```

```
tag: 0x000d
length: 0x0014
=> signature algorithms, content is 20 bytes

content: 0x0012
[
    0x0503 => ecdsa_secp384r1_sha384,
    0x0403 => ecdsa_secp256r1_sha256
    0x0807 => ed25519
    0x0806 => rsa_pss_rsae_sha512
    0x0805 ...
    0x0804 ...
    0x0601 ...
    0x0501 ...
    0x0401 ...
]
```

```
tag: 0x0017 (???)
length: 0000

???? What ????
```

```
tag: 0005
length: 0005
content: 0100000000

tag: 0000
length: 0016
content: 00140000117777772e727573742d6c616e672e6f7267

tag: 0012
length: 0000

tag: 0033
length: 0026
content: 0024001d0020a04d556163020ff655beeacccf1bbc39c1acdf781551caec45e0e145b7995757

tag: 002d
length: 0002
content: 0101

tag: 0023
length: 0000
```