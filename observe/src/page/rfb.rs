//! Browser-to-server RFB framing. Server bytes never enter this parser.

/// A complete client message's disposition.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Decision {
    Pass(Vec<u8>),
    Drop,
    Close(&'static str),
}

#[derive(Default)]
pub(super) struct Gateway {
    bytes: Vec<u8>,
    phase: u8,
    extended_mouse: bool,
    closed: bool,
}

impl Gateway {
    /// Feeds bytes and decides each complete message using the current lease.
    pub fn feed(&mut self, bytes: &[u8], mut holds: impl FnMut() -> bool) -> Vec<Decision> {
        let mut out = Vec::new();
        if self.closed {
            return out;
        }
        // Keep only one bounded message, even if the caller supplies many.
        for &byte in bytes {
            self.bytes.push(byte);
            match self.length() {
                Err(reason) => {
                    self.closed = true;
                    self.bytes.clear();
                    out.push(Decision::Close(reason));
                    break;
                }
                Ok(Some(n)) if self.bytes.len() == n => {
                    let mut message = std::mem::take(&mut self.bytes);
                    let input =
                        self.phase == 3 && matches!(message[0], 4 | 5 | 6 | 250 | 251 | 255);
                    match self.phase {
                        0 => self.phase = 1,
                        1 => self.phase = 2,
                        2 => {
                            message[0] = 1;
                            self.phase = 3;
                        }
                        _ if message[0] == 2 => {
                            self.extended_mouse = message[4..]
                                .as_chunks::<4>()
                                .0
                                .iter()
                                .any(|v| *v == (-316i32).to_be_bytes());
                        }
                        _ => {}
                    }
                    out.push(if input && !holds() {
                        Decision::Drop
                    } else {
                        Decision::Pass(message)
                    });
                }
                _ => {}
            }
        }
        out
    }

    fn length(&self) -> Result<Option<usize>, &'static str> {
        let b = &self.bytes;
        if self.phase == 0 {
            if b.len() == 12 && b != b"RFB 003.008\n" && b != b"RFB 003.007\n" {
                return Err("RFB requires version 3.7 or 3.8");
            }
            return Ok(Some(12));
        }
        if self.phase == 1 {
            return if b[0] == 1 {
                Ok(Some(1))
            } else {
                Err("RFB requires None security type 1")
            };
        }
        if self.phase == 2 {
            return Ok(Some(1));
        }
        let n = match b[0] {
            0 => 20,
            2 if b.len() >= 4 => {
                let n = u16::from_be_bytes([b[2], b[3]]) as usize;
                if n > 64 {
                    return Err("RFB encodings exceed 64");
                }
                4 + 4 * n
            }
            3 | 150 => 10,
            4 => 8,
            5 if b.len() >= 2 => {
                if self.extended_mouse && b[1] & 0x80 != 0 {
                    7
                } else {
                    6
                }
            }
            6 if b.len() >= 8 => {
                let n = i32::from_be_bytes(b[4..8].try_into().unwrap()).unsigned_abs() as usize;
                if n > 1 << 20 {
                    return Err("RFB clipboard exceeds one MiB");
                }
                8 + n
            }
            248 if b.len() >= 9 => {
                if b[8] > 64 {
                    return Err("RFB fence exceeds 64 bytes");
                }
                9 + b[8] as usize
            }
            250 => 4,
            251 if b.len() >= 8 => 8 + 16 * b[6] as usize,
            255 if b.len() >= 2 => {
                if b[1] != 0 {
                    return Err("unknown RFB QEMU subtype");
                }
                12
            }
            2 | 5 | 6 | 248 | 251 | 255 => return Ok(None),
            _ => return Err("unknown RFB client message"),
        };
        Ok(Some(n))
    }
}
