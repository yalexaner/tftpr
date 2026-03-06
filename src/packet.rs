use thiserror::Error;

// TFTP opcodes (RFC 1350)
const OP_RRQ: u16 = 1;
const OP_WRQ: u16 = 2;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;

// TFTP error codes (RFC 1350)
pub const ERR_NOT_DEFINED: u16 = 0;
pub const ERR_FILE_NOT_FOUND: u16 = 1;
pub const ERR_ACCESS_VIOLATION: u16 = 2;
pub const ERR_DISK_FULL: u16 = 3;
pub const ERR_ILLEGAL_OPERATION: u16 = 4;
pub const ERR_FILE_EXISTS: u16 = 6;

/// maximum data payload per DATA packet
pub const MAX_DATA_LEN: usize = 512;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("packet too short")]
    TooShort,
    #[error("unknown opcode: {0}")]
    UnknownOpcode(u16),
    #[error("missing null terminator")]
    MissingNullTerminator,
    #[error("invalid utf-8 string")]
    InvalidUtf8,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Packet {
    Rrq { filename: String, mode: String },
    Wrq { filename: String, mode: String },
    Data { block_num: u16, data: Vec<u8> },
    Ack { block_num: u16 },
    Error { code: u16, message: String },
}

impl Packet {
    pub fn decode(buf: &[u8]) -> Result<Packet, PacketError> {
        if buf.len() < 2 {
            return Err(PacketError::TooShort);
        }

        let opcode = u16::from_be_bytes([buf[0], buf[1]]);
        let rest = &buf[2..];

        match opcode {
            OP_RRQ => {
                let (filename, mode) = parse_request_fields(rest)?;
                Ok(Packet::Rrq { filename, mode })
            }
            OP_WRQ => {
                let (filename, mode) = parse_request_fields(rest)?;
                Ok(Packet::Wrq { filename, mode })
            }
            OP_DATA => {
                if rest.len() < 2 {
                    return Err(PacketError::TooShort);
                }
                let block_num = u16::from_be_bytes([rest[0], rest[1]]);
                let data = rest[2..].to_vec();
                Ok(Packet::Data { block_num, data })
            }
            OP_ACK => {
                if rest.len() < 2 {
                    return Err(PacketError::TooShort);
                }
                let block_num = u16::from_be_bytes([rest[0], rest[1]]);
                Ok(Packet::Ack { block_num })
            }
            OP_ERROR => {
                if rest.len() < 2 {
                    return Err(PacketError::TooShort);
                }
                let code = u16::from_be_bytes([rest[0], rest[1]]);
                let msg_bytes = &rest[2..];
                // error message is null-terminated, but we tolerate missing terminator
                let msg_end = msg_bytes.iter().position(|&b| b == 0).unwrap_or(msg_bytes.len());
                let message = std::str::from_utf8(&msg_bytes[..msg_end])
                    .map_err(|_| PacketError::InvalidUtf8)?
                    .to_string();
                Ok(Packet::Error { code, message })
            }
            other => Err(PacketError::UnknownOpcode(other)),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Packet::Rrq { filename, mode } => encode_request(OP_RRQ, filename, mode),
            Packet::Wrq { filename, mode } => encode_request(OP_WRQ, filename, mode),
            Packet::Data { block_num, data } => {
                let mut buf = Vec::with_capacity(4 + data.len());
                buf.extend_from_slice(&OP_DATA.to_be_bytes());
                buf.extend_from_slice(&block_num.to_be_bytes());
                buf.extend_from_slice(data);
                buf
            }
            Packet::Ack { block_num } => {
                let mut buf = Vec::with_capacity(4);
                buf.extend_from_slice(&OP_ACK.to_be_bytes());
                buf.extend_from_slice(&block_num.to_be_bytes());
                buf
            }
            Packet::Error { code, message } => {
                let mut buf = Vec::with_capacity(5 + message.len());
                buf.extend_from_slice(&OP_ERROR.to_be_bytes());
                buf.extend_from_slice(&code.to_be_bytes());
                buf.extend_from_slice(message.as_bytes());
                buf.push(0);
                buf
            }
        }
    }
}

fn parse_request_fields(buf: &[u8]) -> Result<(String, String), PacketError> {
    let first_null = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or(PacketError::MissingNullTerminator)?;

    let filename = std::str::from_utf8(&buf[..first_null])
        .map_err(|_| PacketError::InvalidUtf8)?
        .to_string();

    let after_first = &buf[first_null + 1..];
    let second_null = after_first
        .iter()
        .position(|&b| b == 0)
        .ok_or(PacketError::MissingNullTerminator)?;

    let mode = std::str::from_utf8(&after_first[..second_null])
        .map_err(|_| PacketError::InvalidUtf8)?
        .to_string();

    Ok((filename, mode))
}

fn encode_request(opcode: u16, filename: &str, mode: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + filename.len() + mode.len());
    buf.extend_from_slice(&opcode.to_be_bytes());
    buf.extend_from_slice(filename.as_bytes());
    buf.push(0);
    buf.extend_from_slice(mode.as_bytes());
    buf.push(0);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    // round-trip tests

    #[test]
    fn roundtrip_rrq() {
        let pkt = Packet::Rrq {
            filename: "test.txt".into(),
            mode: "octet".into(),
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn roundtrip_wrq() {
        let pkt = Packet::Wrq {
            filename: "upload.bin".into(),
            mode: "netascii".into(),
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn roundtrip_data() {
        let pkt = Packet::Data {
            block_num: 1,
            data: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn roundtrip_ack() {
        let pkt = Packet::Ack { block_num: 42 };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn roundtrip_error() {
        let pkt = Packet::Error {
            code: ERR_FILE_NOT_FOUND,
            message: "file not found".into(),
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    // edge cases

    #[test]
    fn data_empty_payload() {
        let pkt = Packet::Data {
            block_num: 5,
            data: vec![],
        };
        let encoded = pkt.encode();
        assert_eq!(encoded.len(), 4);
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn data_max_block() {
        let data = vec![0xAB; MAX_DATA_LEN];
        let pkt = Packet::Data {
            block_num: 1,
            data: data.clone(),
        };
        let encoded = pkt.encode();
        assert_eq!(encoded.len(), 4 + MAX_DATA_LEN);
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn rrq_empty_filename() {
        let pkt = Packet::Rrq {
            filename: "".into(),
            mode: "octet".into(),
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn error_empty_message() {
        let pkt = Packet::Error {
            code: ERR_NOT_DEFINED,
            message: "".into(),
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    // malformed packet tests

    #[test]
    fn too_short_empty() {
        assert!(matches!(
            Packet::decode(&[]),
            Err(PacketError::TooShort)
        ));
    }

    #[test]
    fn too_short_one_byte() {
        assert!(matches!(
            Packet::decode(&[0x00]),
            Err(PacketError::TooShort)
        ));
    }

    #[test]
    fn unknown_opcode() {
        let buf = [0x00, 0x09]; // opcode 9 does not exist
        assert!(matches!(
            Packet::decode(&buf),
            Err(PacketError::UnknownOpcode(9))
        ));
    }

    #[test]
    fn rrq_missing_null_terminators() {
        // opcode 1 followed by bytes with no null
        let buf = [0x00, 0x01, b'f', b'o', b'o'];
        assert!(matches!(
            Packet::decode(&buf),
            Err(PacketError::MissingNullTerminator)
        ));
    }

    #[test]
    fn rrq_missing_second_null() {
        // filename null-terminated, but mode is not
        let buf = [0x00, 0x01, b'f', 0x00, b'o', b'c', b't'];
        assert!(matches!(
            Packet::decode(&buf),
            Err(PacketError::MissingNullTerminator)
        ));
    }

    #[test]
    fn data_missing_block_num() {
        // opcode 3 with only 1 byte after
        let buf = [0x00, 0x03, 0x00];
        assert!(matches!(
            Packet::decode(&buf),
            Err(PacketError::TooShort)
        ));
    }

    #[test]
    fn ack_missing_block_num() {
        // opcode 4 with no block num
        let buf = [0x00, 0x04];
        assert!(matches!(
            Packet::decode(&buf),
            Err(PacketError::TooShort)
        ));
    }

    #[test]
    fn error_missing_code() {
        let buf = [0x00, 0x05, 0x00];
        assert!(matches!(
            Packet::decode(&buf),
            Err(PacketError::TooShort)
        ));
    }

    // encoding format tests

    #[test]
    fn rrq_wire_format() {
        let pkt = Packet::Rrq {
            filename: "a".into(),
            mode: "octet".into(),
        };
        let buf = pkt.encode();
        assert_eq!(buf[0..2], [0x00, 0x01]); // opcode
        assert_eq!(buf[2], b'a');
        assert_eq!(buf[3], 0x00); // null after filename
        assert_eq!(&buf[4..9], b"octet");
        assert_eq!(buf[9], 0x00); // null after mode
    }

    #[test]
    fn ack_wire_format() {
        let pkt = Packet::Ack { block_num: 0x0102 };
        let buf = pkt.encode();
        assert_eq!(buf, [0x00, 0x04, 0x01, 0x02]);
    }
}
