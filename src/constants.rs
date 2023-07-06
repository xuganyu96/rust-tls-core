use std::error::Error;

/// Each type is exactly one byte wide
#[allow(dead_code)]
#[derive(Debug,Clone)]
pub(crate) enum ContentType {
    Invalid,
    ChangeCipherSpec,
    Alert,
    Handshake,
    ApplicationData,
}

impl TryFrom<ContentType> for u8 {
    type Error = Box<dyn Error>;

    fn try_from(value: ContentType) -> Result<Self, Self::Error> {
        match value {
            ContentType::Invalid => Ok(0x00),
            ContentType::ChangeCipherSpec => Ok(0x14),
            ContentType::Alert => Ok(0x15),
            ContentType::Handshake => Ok(0x16),
            ContentType::ApplicationData => Ok(0x17),
        }
    }
}

/// Each type is exactly two-byte wide
#[allow(dead_code)]
#[derive(Debug,Clone)]
pub(crate) enum ProtocolVersion {
    TLSv1_0,  // 0x0301
    TLSv1_1,  // 0x0302
    TLSv1_2,  // 0x0303
    TLSv1_3,  // 0x0304
}  

impl TryFrom<ProtocolVersion> for [u8; 2] {
    type Error = Box<dyn Error>;

    fn try_from(value: ProtocolVersion) -> Result<Self, Self::Error> {
        match value {
            ProtocolVersion::TLSv1_0 => Ok([0x03, 0x01]),
            ProtocolVersion::TLSv1_1 => Ok([0x03, 0x02]),
            ProtocolVersion::TLSv1_2 => Ok([0x03, 0x03]),
            ProtocolVersion::TLSv1_3 => Ok([0x03, 0x04]),
        }
    }
}

