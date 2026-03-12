use thiserror::Error;

// TFTP opcodes (RFC 1350)
const OP_RRQ: u16 = 1;
const OP_WRQ: u16 = 2;
const OP_DATA: u16 = 3;
const OP_ACK: u16 = 4;
const OP_ERROR: u16 = 5;
const OP_OACK: u16 = 6;

// TFTP error codes (RFC 1350)
pub const ERR_NOT_DEFINED: u16 = 0;
pub const ERR_FILE_NOT_FOUND: u16 = 1;
pub const ERR_ACCESS_VIOLATION: u16 = 2;
pub const ERR_DISK_FULL: u16 = 3;
pub const ERR_ILLEGAL_OPERATION: u16 = 4;
pub const ERR_FILE_EXISTS: u16 = 6;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Options {
    pub blksize: Option<u16>,
}

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
    Rrq {
        filename: String,
        mode: String,
        options: Options,
    },
    Wrq {
        filename: String,
        mode: String,
        options: Options,
    },
    Data {
        block_num: u16,
        data: Vec<u8>,
    },
    Ack {
        block_num: u16,
    },
    Error {
        code: u16,
        message: String,
    },
    Oack {
        options: Options,
    },
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
                let (filename, mode, options) = parse_request_fields(rest)?;
                Ok(Packet::Rrq {
                    filename,
                    mode,
                    options,
                })
            }
            OP_WRQ => {
                let (filename, mode, options) = parse_request_fields(rest)?;
                Ok(Packet::Wrq {
                    filename,
                    mode,
                    options,
                })
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
                let msg_end = msg_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(msg_bytes.len());
                let message = std::str::from_utf8(&msg_bytes[..msg_end])
                    .map_err(|_| PacketError::InvalidUtf8)?
                    .to_string();
                Ok(Packet::Error { code, message })
            }
            OP_OACK => {
                let options = parse_options(rest);
                Ok(Packet::Oack { options })
            }
            other => Err(PacketError::UnknownOpcode(other)),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Packet::Rrq {
                filename,
                mode,
                options,
            } => encode_request(OP_RRQ, filename, mode, options),
            Packet::Wrq {
                filename,
                mode,
                options,
            } => encode_request(OP_WRQ, filename, mode, options),
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
            Packet::Oack { options } => {
                let mut buf = Vec::new();
                buf.extend_from_slice(&OP_OACK.to_be_bytes());
                encode_options(options, &mut buf);
                buf
            }
        }
    }
}

type RequestFields = (String, String, Options);

fn parse_request_fields(buf: &[u8]) -> Result<RequestFields, PacketError> {
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

    let options_buf = &after_first[second_null + 1..];
    let options = parse_options(options_buf);

    Ok((filename, mode, options))
}

/// parses null-terminated key/value option pairs from a buffer into a
/// typed Options struct. unknown keys are silently ignored. malformed
/// trailing data (key without value, missing null) is silently ignored
/// for graceful degradation.
fn parse_options(buf: &[u8]) -> Options {
    let mut options = Options::default();
    let mut pos = 0;

    while pos < buf.len() {
        let key_end = match buf[pos..].iter().position(|&b| b == 0) {
            Some(p) => p,
            None => break,
        };
        let key = match std::str::from_utf8(&buf[pos..pos + key_end]) {
            Ok(s) => s,
            Err(_) => break,
        };
        pos += key_end + 1;

        if pos >= buf.len() {
            break;
        }

        let val_end = match buf[pos..].iter().position(|&b| b == 0) {
            Some(p) => p,
            None => break,
        };
        let value = match std::str::from_utf8(&buf[pos..pos + val_end]) {
            Ok(s) => s,
            Err(_) => break,
        };
        pos += val_end + 1;

        if key.eq_ignore_ascii_case("blksize") {
            // parse as u32 first to handle values > u16::MAX, then clamp
            if let Ok(v) = value.parse::<u32>() {
                options.blksize = Some(v.min(u16::MAX as u32) as u16);
            }
        }
        // unknown options silently ignored
    }

    options
}

fn encode_request(opcode: u16, filename: &str, mode: &str, options: &Options) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + filename.len() + mode.len());
    buf.extend_from_slice(&opcode.to_be_bytes());
    buf.extend_from_slice(filename.as_bytes());
    buf.push(0);
    buf.extend_from_slice(mode.as_bytes());
    buf.push(0);
    encode_options(options, &mut buf);
    buf
}

fn encode_options(options: &Options, buf: &mut Vec<u8>) {
    if let Some(blksize) = options.blksize {
        buf.extend_from_slice(b"blksize");
        buf.push(0);
        let val = blksize.to_string();
        buf.extend_from_slice(val.as_bytes());
        buf.push(0);
    }
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
            options: Options::default(),
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
            options: Options::default(),
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
        let data = vec![0xAB; 512];
        let pkt = Packet::Data {
            block_num: 1,
            data: data.clone(),
        };
        let encoded = pkt.encode();
        assert_eq!(encoded.len(), 4 + 512);
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn rrq_empty_filename() {
        let pkt = Packet::Rrq {
            filename: "".into(),
            mode: "octet".into(),
            options: Options::default(),
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
        assert!(matches!(Packet::decode(&[]), Err(PacketError::TooShort)));
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
        assert!(matches!(Packet::decode(&buf), Err(PacketError::TooShort)));
    }

    #[test]
    fn ack_missing_block_num() {
        // opcode 4 with no block num
        let buf = [0x00, 0x04];
        assert!(matches!(Packet::decode(&buf), Err(PacketError::TooShort)));
    }

    #[test]
    fn error_missing_code() {
        let buf = [0x00, 0x05, 0x00];
        assert!(matches!(Packet::decode(&buf), Err(PacketError::TooShort)));
    }

    // encoding format tests

    #[test]
    fn rrq_wire_format() {
        let pkt = Packet::Rrq {
            filename: "a".into(),
            mode: "octet".into(),
            options: Options::default(),
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

    // OACK and options tests

    #[test]
    fn roundtrip_oack_empty_options() {
        let pkt = Packet::Oack {
            options: Options::default(),
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn roundtrip_oack_single_option() {
        let pkt = Packet::Oack {
            options: Options {
                blksize: Some(1024),
            },
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn oack_wire_format() {
        let pkt = Packet::Oack {
            options: Options { blksize: Some(512) },
        };
        let buf = pkt.encode();
        // [00 06] [blksize\0] [512\0]
        assert_eq!(buf[0..2], [0x00, 0x06]);
        assert_eq!(&buf[2..9], b"blksize");
        assert_eq!(buf[9], 0x00);
        assert_eq!(&buf[10..13], b"512");
        assert_eq!(buf[13], 0x00);
    }

    #[test]
    fn roundtrip_rrq_with_options() {
        let pkt = Packet::Rrq {
            filename: "test.txt".into(),
            mode: "octet".into(),
            options: Options {
                blksize: Some(1024),
            },
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn roundtrip_wrq_with_options() {
        let pkt = Packet::Wrq {
            filename: "upload.bin".into(),
            mode: "octet".into(),
            options: Options {
                blksize: Some(8192),
            },
        };
        let encoded = pkt.encode();
        let decoded = Packet::decode(&encoded).unwrap();
        assert_eq!(pkt, decoded);
    }

    #[test]
    fn wrq_with_unknown_options_ignored() {
        // wire bytes with blksize + tsize (unknown) — tsize should be silently ignored
        let mut buf = vec![0x00, 0x02]; // WRQ opcode
        buf.extend_from_slice(b"upload.bin");
        buf.push(0);
        buf.extend_from_slice(b"octet");
        buf.push(0);
        buf.extend_from_slice(b"blksize");
        buf.push(0);
        buf.extend_from_slice(b"8192");
        buf.push(0);
        buf.extend_from_slice(b"tsize");
        buf.push(0);
        buf.extend_from_slice(b"0");
        buf.push(0);
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Wrq {
                filename: "upload.bin".into(),
                mode: "octet".into(),
                options: Options {
                    blksize: Some(8192),
                },
            }
        );
    }

    #[test]
    fn rrq_without_options_backward_compat() {
        // raw wire bytes: RRQ without any options after mode
        let mut buf = vec![0x00, 0x01]; // opcode
        buf.extend_from_slice(b"file.txt");
        buf.push(0);
        buf.extend_from_slice(b"octet");
        buf.push(0);
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Rrq {
                filename: "file.txt".into(),
                mode: "octet".into(),
                options: Options::default(),
            }
        );
    }

    #[test]
    fn wrq_without_options_backward_compat() {
        let mut buf = vec![0x00, 0x02]; // opcode
        buf.extend_from_slice(b"data.bin");
        buf.push(0);
        buf.extend_from_slice(b"octet");
        buf.push(0);
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Wrq {
                filename: "data.bin".into(),
                mode: "octet".into(),
                options: Options::default(),
            }
        );
    }

    #[test]
    fn oack_malformed_odd_fields_silently_ignored() {
        // OACK with a key but no value — gracefully degrades to empty options
        let mut buf = vec![0x00, 0x06]; // opcode
        buf.extend_from_slice(b"blksize");
        buf.push(0);
        // no value follows — key without value
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Oack {
                options: Options::default(),
            }
        );
    }

    #[test]
    fn oack_malformed_missing_null_silently_ignored() {
        // OACK with key but value has no null terminator — gracefully degrades
        let mut buf = vec![0x00, 0x06]; // opcode
        buf.extend_from_slice(b"blksize");
        buf.push(0);
        buf.extend_from_slice(b"1024"); // no trailing null
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Oack {
                options: Options::default(),
            }
        );
    }

    #[test]
    fn rrq_with_options_wire_format() {
        let pkt = Packet::Rrq {
            filename: "f".into(),
            mode: "octet".into(),
            options: Options {
                blksize: Some(1024),
            },
        };
        let buf = pkt.encode();
        // [00 01][f\0][octet\0][blksize\0][1024\0]
        assert_eq!(buf[0..2], [0x00, 0x01]);
        assert_eq!(buf[2], b'f');
        assert_eq!(buf[3], 0x00);
        assert_eq!(&buf[4..9], b"octet");
        assert_eq!(buf[9], 0x00);
        assert_eq!(&buf[10..17], b"blksize");
        assert_eq!(buf[17], 0x00);
        assert_eq!(&buf[18..22], b"1024");
        assert_eq!(buf[22], 0x00);
    }

    #[test]
    fn parse_blksize_above_u16_max_clamped() {
        // client sends blksize=70000 which exceeds u16::MAX (65535)
        // should be clamped to u16::MAX
        let mut buf = vec![0x00, 0x01]; // RRQ opcode
        buf.extend_from_slice(b"f");
        buf.push(0);
        buf.extend_from_slice(b"octet");
        buf.push(0);
        buf.extend_from_slice(b"blksize");
        buf.push(0);
        buf.extend_from_slice(b"70000");
        buf.push(0);
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Rrq {
                filename: "f".into(),
                mode: "octet".into(),
                options: Options {
                    blksize: Some(u16::MAX),
                },
            }
        );
    }

    #[test]
    fn parse_blksize_overflow_u32_returns_none() {
        // client sends a blksize value that overflows u32 — should result in
        // blksize: None (parse failure silently ignored)
        let mut buf = vec![0x00, 0x01]; // RRQ opcode
        buf.extend_from_slice(b"f");
        buf.push(0);
        buf.extend_from_slice(b"octet");
        buf.push(0);
        buf.extend_from_slice(b"blksize");
        buf.push(0);
        buf.extend_from_slice(b"99999999999");
        buf.push(0);
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Rrq {
                filename: "f".into(),
                mode: "octet".into(),
                options: Options::default(),
            }
        );
    }

    #[test]
    fn parse_options_case_insensitive() {
        let mut buf = vec![0x00, 0x01]; // RRQ opcode
        buf.extend_from_slice(b"f");
        buf.push(0);
        buf.extend_from_slice(b"octet");
        buf.push(0);
        buf.extend_from_slice(b"BLKSIZE");
        buf.push(0);
        buf.extend_from_slice(b"1024");
        buf.push(0);
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Rrq {
                filename: "f".into(),
                mode: "octet".into(),
                options: Options {
                    blksize: Some(1024),
                },
            }
        );
    }

    #[test]
    fn parse_unknown_options_only() {
        // only unknown options — blksize should remain None
        let mut buf = vec![0x00, 0x01]; // RRQ opcode
        buf.extend_from_slice(b"f");
        buf.push(0);
        buf.extend_from_slice(b"octet");
        buf.push(0);
        buf.extend_from_slice(b"tsize");
        buf.push(0);
        buf.extend_from_slice(b"0");
        buf.push(0);
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Rrq {
                filename: "f".into(),
                mode: "octet".into(),
                options: Options::default(),
            }
        );
    }

    #[test]
    fn parse_blksize_non_numeric_ignored() {
        // non-numeric blksize value should be silently ignored
        let mut buf = vec![0x00, 0x01]; // RRQ opcode
        buf.extend_from_slice(b"f");
        buf.push(0);
        buf.extend_from_slice(b"octet");
        buf.push(0);
        buf.extend_from_slice(b"blksize");
        buf.push(0);
        buf.extend_from_slice(b"abc");
        buf.push(0);
        let decoded = Packet::decode(&buf).unwrap();
        assert_eq!(
            decoded,
            Packet::Rrq {
                filename: "f".into(),
                mode: "octet".into(),
                options: Options::default(),
            }
        );
    }
}
