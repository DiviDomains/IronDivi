// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! The pipe between a collector process and the parent: length-prefixed
//! frames on the child's stdout. `F` opens a file in the package (a path
//! relative to the package root), `D` appends bytes to it. The parent
//! scrubs every `D` frame before it reaches the disk, so a collector cuts
//! its frames at line ends ([`Out`] does) and a pattern never straddles two.

use std::io::{Read, Write};

pub const MAX_FRAME: usize = 256 * 1024;

pub enum Frame {
    File(String),
    Data(Vec<u8>),
}

pub fn read_frame(r: &mut impl Read) -> std::io::Result<Option<Frame>> {
    let mut head = [0u8; 5];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_le_bytes([head[1], head[2], head[3], head[4]]) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other(format!("frame of {len} bytes")));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body)?;
    match head[0] {
        b'F' => Ok(Some(Frame::File(String::from_utf8_lossy(&body).into_owned()))),
        b'D' => Ok(Some(Frame::Data(body))),
        t => Err(std::io::Error::other(format!("frame type {t}"))),
    }
}

/// The collector side: buffered per file, flushed at line ends so the
/// parent's scrub sees whole lines, and on every file switch, so a killed
/// collector loses at most the last partial line
pub struct Out {
    w: std::io::Stdout,
    buf: Vec<u8>,
    open: bool,
}

impl Default for Out {
    fn default() -> Self {
        Self::new()
    }
}

impl Out {
    pub fn new() -> Self {
        Out { w: std::io::stdout(), buf: Vec::new(), open: false }
    }

    fn frame(&mut self, t: u8, body: &[u8]) {
        let mut lock = self.w.lock();
        let _ = lock.write_all(&[t]);
        let _ = lock.write_all(&(body.len() as u32).to_le_bytes());
        let _ = lock.write_all(body);
        let _ = lock.flush();
    }

    /// Start (or append to) a file of the package
    pub fn file(&mut self, rel: &str) {
        self.flush();
        self.frame(b'F', rel.as_bytes());
        self.open = true;
    }

    pub fn write(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        if self.buf.len() >= 32 * 1024 {
            // flush up to the last newline
            if let Some(pos) = self.buf.iter().rposition(|&b| b == b'\n') {
                let rest = self.buf.split_off(pos + 1);
                let chunk = std::mem::replace(&mut self.buf, rest);
                self.send(&chunk);
            } else if self.buf.len() >= MAX_FRAME / 2 {
                let chunk = std::mem::take(&mut self.buf);
                self.send(&chunk);
            }
        }
    }

    pub fn line(&mut self, s: &str) {
        self.write(s.as_bytes());
        self.write(b"\n");
    }

    fn send(&mut self, chunk: &[u8]) {
        if !self.open {
            self.frame(b'F', b"diag.log");
            self.open = true;
        }
        for part in chunk.chunks(MAX_FRAME) {
            self.frame(b'D', part);
        }
    }

    pub fn flush(&mut self) {
        if !self.buf.is_empty() {
            let chunk = std::mem::take(&mut self.buf);
            self.send(&chunk);
        }
    }
}

impl Drop for Out {
    fn drop(&mut self) {
        self.flush();
    }
}

/// `writeln!`-style helper for [`Out`]
#[macro_export]
macro_rules! outln {
    ($o:expr) => { $o.line("") };
    ($o:expr, $($a:tt)*) => { $o.line(&format!($($a)*)) };
}
