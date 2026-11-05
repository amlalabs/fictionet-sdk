//! Optional byte-oriented line editing for an SSH shell.
//!
//! SSH channels carry raw bytes. An application may feed those bytes here when
//! it wants a small canonical terminal; exec and subsystem streams need no such
//! layer. This is not a shell, a terminal emulator, or a Unicode display editor.
//! Erase removes one byte. Echo is appended to the caller's output, at most
//! three bytes per retained byte for a line kill. Drain that output regularly.

/// One completed terminal action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    /// A line without its terminator, preserving non-ASCII bytes.
    Line(Vec<u8>),
    /// Control-C canceled the pending line.
    Interrupt,
    /// Control-D on an empty line ended input.
    End,
}

/// The line exceeded its configured bound and is discarded, never executed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineTooLong;

impl std::fmt::Display for LineTooLong {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("terminal line is too long")
    }
}

impl std::error::Error for LineTooLong {}

/// A bounded canonical line buffer with optional echo.
#[derive(Clone, Debug)]
pub struct Terminal {
    line: Vec<u8>,
    limit: usize,
    echo: bool,
    after_cr: bool,
    discarding: bool,
    ended: bool,
}

impl Terminal {
    /// Retain at most `max_line_bytes` bytes of one line; echo starts enabled.
    pub fn new(max_line_bytes: usize) -> Self {
        Self {
            line: Vec::new(),
            limit: max_line_bytes,
            echo: true,
            after_cr: false,
            discarding: false,
            ended: false,
        }
    }

    /// Enable or disable echo without changing the buffered input.
    pub fn set_echo(&mut self, echo: bool) {
        self.echo = echo;
    }

    /// Bytes retained in the current line.
    pub fn pending(&self) -> &[u8] {
        &self.line
    }

    /// Allocated line storage for the application's connection budget.
    pub fn held(&self) -> usize {
        self.line.capacity()
    }

    /// Consume one raw byte and append any echo to `output`.
    ///
    /// CR, LF and CRLF each terminate one line, including across reads.
    /// Backspace and DEL erase a byte, Control-U kills the line, and Control-C
    /// interrupts it. Control-D submits a nonempty line without echoing a newline;
    /// on an empty line it ends input. Other controls except tab are ignored.
    ///
    /// An overlong line reports one error and discards input until a terminator,
    /// Control-C or Control-U. No partial line event is emitted. After `End`,
    /// further input is ignored. The caller owns EOF and channel lifetime.
    pub fn push(&mut self, byte: u8, output: &mut Vec<u8>) -> Result<Option<Event>, LineTooLong> {
        if self.ended {
            return Ok(None);
        }
        let after_cr = std::mem::replace(&mut self.after_cr, byte == b'\r');
        if byte == b'\n' && after_cr {
            return Ok(None);
        }
        if self.discarding && !matches!(byte, b'\r' | b'\n' | 3 | 21) {
            return Ok(None);
        }
        match byte {
            b'\r' | b'\n' => {
                self.echo_bytes(output, b"\r\n");
                if std::mem::take(&mut self.discarding) {
                    self.line.clear();
                    return Ok(None);
                }
                Ok(Some(Event::Line(std::mem::take(&mut self.line))))
            }
            3 => {
                self.line.clear();
                self.discarding = false;
                self.echo_bytes(output, b"^C\r\n");
                Ok(Some(Event::Interrupt))
            }
            4 if self.line.is_empty() => {
                self.ended = true;
                Ok(Some(Event::End))
            }
            4 => Ok(Some(Event::Line(std::mem::take(&mut self.line)))),
            8 | 127 => {
                if self.line.pop().is_some() {
                    self.echo_bytes(output, b"\x08 \x08");
                }
                Ok(None)
            }
            21 => {
                if self.echo {
                    for _ in 0..self.line.len() {
                        output.extend_from_slice(b"\x08 \x08");
                    }
                }
                self.line.clear();
                self.discarding = false;
                Ok(None)
            }
            b'\t' | 32..=126 | 128..=255 => {
                if self.line.len() == self.limit {
                    self.discarding = true;
                    return Err(LineTooLong);
                }
                self.line.push(byte);
                self.echo_bytes(output, &[byte]);
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn echo_bytes(&self, output: &mut Vec<u8>, bytes: &[u8]) {
        if self.echo {
            output.extend_from_slice(bytes);
        }
    }
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new(4096)
    }
}
