//! TLS Records are the top layer abstraction that are serialized first before
//! being sent into the TCP stream
use crate::constants::{ContentType, ProtocolVersion};

/// Record is the top layer abstraction that is serialized into the TCP stream
#[allow(dead_code)]
enum Record<T> {
    TLSPlaintext(TLSPlaintext<T>),
    TLSCiphertext(TLSCiphertext<T>),
}

/// Where the payload types can be converted into byte arrays, the record
/// itself can also be converted into byte arrays
impl<T> From<Record<T>> for Vec<u8>
where
    T: Into<Vec<u8>>,
{
    fn from(value: Record<T>) -> Self {
        match value {
            Record::TLSPlaintext(pt) => pt.into(),
            Record::TLSCiphertext(ct) => ct.into(),
        }
    }
}

/// TLS Plaintext is sent for negotiating cryptographic parameters, including
/// ClientHello, HelloRetryRequest, and ServerHello
#[allow(dead_code)]
struct TLSPlaintext<Payload> {
    content_type: ContentType,
    legacy_record_version: ProtocolVersion,
    length: u16,

    /// TODO: we don't actually know what specific type will be in the
    /// TLSPlaintext struct, since it depends on the content_type, so instead
    /// of declaring a concrete type, a type parameter is used
    fragment: Payload,
}

impl<T: Into<Vec<u8>>> From<TLSPlaintext<T>> for Vec<u8> {
    fn from(value: TLSPlaintext<T>) -> Self {
        let mut buf = vec![];
        let content_type: u8 = value.content_type.try_into().unwrap();
        let record_version: [u8; 2] = value.legacy_record_version.try_into().unwrap();
        let length = value.length.to_be_bytes();
        let fragment: Vec<u8> = value.fragment.into();

        buf.push(content_type);
        buf.extend_from_slice(&record_version);
        buf.extend_from_slice(&length);
        buf.extend_from_slice(&fragment);

        return buf;
    }
}

#[allow(dead_code)]
struct TLSCiphertext<Payload> {
    /// Always set to ContentType::ApplicationData
    opaque_type: ContentType,

    /// Always set to ProtocolVersion::TLSv1_2
    legacy_record_version: ProtocolVersion,

    length: u16,

    encrypted_record: Payload,
}

impl<T: Into<Vec<u8>>> From<TLSCiphertext<T>> for Vec<u8> {
    fn from(value: TLSCiphertext<T>) -> Self {
        let mut buf = vec![];
        buf.push(value.opaque_type.try_into().unwrap());

        let record_version: [u8; 2] = value.legacy_record_version.try_into().unwrap();
        buf.extend_from_slice(&record_version);
        buf.extend_from_slice(&value.length.to_be_bytes());
        buf.extend_from_slice(&value.encrypted_record.into());

        return buf;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_blind_serialization() {
        let content = vec![0, 1, 2, 3, 4];
        let length: u16 = content.len().try_into().unwrap();
        let record: Record<Vec<u8>> = Record::TLSPlaintext(TLSPlaintext {
            content_type: ContentType::ApplicationData,
            legacy_record_version: ProtocolVersion::TLSv1_0,
            length,
            fragment: content,
        });
        let record: Vec<u8> = record.into();

        assert_eq!(record, vec![23, 0x03, 0x01, 0x00, 0x05, 0, 1, 2, 3, 4]);
    }
}
