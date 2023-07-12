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

#[allow(dead_code)]
enum RecordLayerParser<'a> {
    ExpectContentType {
        remainder: &'a [u8],
    },
    ExpectProtocolVersion {
        content_type: ContentType,
        remainder: &'a [u8],
    },
    ExpectLength {
        content_type: ContentType,
        protocol_version: ProtocolVersion,
        remainder: &'a [u8],
    },
    ExpectContent,
    Failed,
    Finished,
}

#[allow(dead_code)]
impl<'a> RecordLayerParser<'a> {
    /// The finite state machine always start with "ExpectContentType"
    fn start(remainder: &'a [u8]) -> Self {
        return Self::ExpectContentType { remainder };
    }

    fn is_failed(&self) -> bool {
        match self {
            Self::Failed => true,
            _ => false,
        }
    }

    /// Attempt to extract the content_type encoding from the remainder of the
    /// received bytes. If there is a valid content_type encoding, return
    /// Self::ExpectProtocolVersion, otherwise return Self::Failed
    fn parse_content_type(self) -> Self {
        let remainder = match self {
            Self::ExpectContentType { remainder } => remainder,
            _ => unreachable!(),
        };
        if remainder.len() < 1 {
            // TODO: Failed because content_type encoding is missing
            return Self::Failed;
        }
        // Unwrap is ok because there is guaranteed to be at least one byte
        let encoding = remainder.get(0).unwrap();
        return match ContentType::try_from(encoding.clone()) {
            Ok(content_type) => Self::ExpectProtocolVersion {
                content_type,
                remainder: &remainder[1..],
            },
            Err(_) => {
                // TODO: failed because is encoding is invalid
                Self::Failed
            }
        };
    }

    /// Attempt to extract the protocol version encoding from the remainder of
    /// the received bytes. If there is a valid protocol_version encoding,
    /// return Self::ExpectLength, else return Self.Failed
    fn parse_protocol_version(self) -> Self {
        let (content_type, remainder) = match self {
            Self::ExpectProtocolVersion {
                content_type,
                remainder,
            } => (content_type, remainder),
            _ => unreachable!(),
        };

        return match ProtocolVersion::try_from(remainder) {
            Ok(protocol_version) => Self::ExpectLength {
                content_type,
                protocol_version,
                remainder: remainder.get(2..).unwrap(),
            },
            Err(_) => Self::Failed,
        };
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

    #[test]
    fn test_parse_content_type() {
        let start = RecordLayerParser::start(&[0x16, 1, 2, 3, 4]);
        match start.parse_content_type() {
            RecordLayerParser::ExpectProtocolVersion {
                content_type,
                remainder,
            } => {
                assert_eq!(content_type, ContentType::Handshake);
                assert_eq!(remainder, &[1, 2, 3, 4]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn missing_content_type() {
        let start = RecordLayerParser::start(&[]);
        assert!(start.parse_content_type().is_failed());
    }

    #[test]
    fn invalid_content_type_encoding() {
        let start = RecordLayerParser::start(&[0xff, 2, 3, 4]);
        assert!(start.parse_content_type().is_failed());
    }

    #[test]
    fn parse_protocol_version() {
        let start = RecordLayerParser::ExpectProtocolVersion {
            content_type: ContentType::Handshake,
            remainder: &[0x03, 0x03, 1, 2, 3],
        };

        match start.parse_protocol_version() {
            RecordLayerParser::ExpectLength {
                content_type,
                protocol_version,
                remainder,
            } => {
                assert_eq!(content_type, ContentType::Handshake);
                assert_eq!(protocol_version, ProtocolVersion::TLSv1_2);
                assert_eq!(remainder, &[1, 2, 3]);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn missing_protocol_version() {
        let start = RecordLayerParser::ExpectProtocolVersion {
            content_type: ContentType::Handshake,
            remainder: &[0x03],
        };

        assert!(start.parse_protocol_version().is_failed());
    }

    #[test]
    fn invalid_protocol_version_encoding() {
        let start = RecordLayerParser::ExpectProtocolVersion {
            content_type: ContentType::Handshake,
            remainder: &[0x03, 0x05, 1, 2, 3], // TLS v1.4?
        };

        assert!(start.parse_protocol_version().is_failed());
    }
}
