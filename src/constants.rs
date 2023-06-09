use std::error::Error;

/// Each type is exactly one byte wide
#[allow(dead_code)]
#[derive(Debug,Clone,Eq,PartialEq)]
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

impl TryFrom<u8> for ContentType {
    type Error = Box<dyn Error>;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        return match value {
            0x00 => Ok(Self::Invalid),
            0x14 => Ok(Self::ChangeCipherSpec),
            0x15 => Ok(Self::Alert),
            0x16 => Ok(Self::Handshake),
            0x17 => Ok(Self::ApplicationData),
            _ => Err("Invalid encoding".into()),
        };
    }
}

/// Each type is exactly two-byte wide
#[allow(dead_code)]
#[derive(Debug,Clone,Eq,PartialEq)]
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

impl TryFrom<&[u8]> for ProtocolVersion {
    type Error = Box<dyn Error>;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 2 {
            return Err("Invalid length".into());
        }

        // TODO: unwrap is okay since the length is guaranteed
        return match value.get(0..2).unwrap() {
            &[0x03, 0x01] => Ok(Self::TLSv1_0),
            &[0x03, 0x02] => Ok(Self::TLSv1_1),
            &[0x03, 0x03] => Ok(Self::TLSv1_2),
            &[0x03, 0x04] => Ok(Self::TLSv1_3),
            _ => Err("Invalid encoding".into()),
        };
    }
}
