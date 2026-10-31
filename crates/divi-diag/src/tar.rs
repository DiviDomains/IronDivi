// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi

//! A minimal ustar reader and writer (POSIX.1-1988 with the GNU long-name
//! and pax `path` extensions on the reading side). B6.4 reads
//! `tar -cf - . | irondivi-cli diag --import -` from stdin without the
//! unredacted data touching the disk; §8 packs the folder it shows the
//! user. Only regular files are carried; anything else is reported.

use std::io::{self, Read, Write};

pub const BLOCK: usize = 512;

/// One member as read: a regular file's bytes, or why it was not taken
pub enum Member {
    File { name: String, data: Vec<u8> },
    Skipped { name: String, why: String },
}

fn octal(field: &[u8]) -> Result<u64, String> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return Err("base-256 size field (a member over 8 GB)".into());
    }
    let s: String = field.iter().take_while(|b| **b != 0).map(|b| *b as char).collect();
    let s = s.trim();
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 8).map_err(|_| "a header field that is not octal".to_string())
}

fn cstr(field: &[u8]) -> String {
    let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
    crate::util::escape_bytes(&field[..end])
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn skip<R: Read>(r: &mut R, n: u64) -> io::Result<()> {
    let copied = io::copy(&mut r.take(n), &mut io::sink())?;
    if copied < n {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "archive ends inside a member"));
    }
    Ok(())
}

fn padding(size: u64) -> u64 {
    (BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64
}

/// `path=` from a pax extended header's records (`<len> path=<value>\n`)
fn pax_path(data: &[u8]) -> Option<String> {
    let mut rest = data;
    while !rest.is_empty() {
        let sp = rest.iter().position(|b| *b == b' ')?;
        let len: usize = std::str::from_utf8(&rest[..sp]).ok()?.parse().ok()?;
        if len <= sp || len > rest.len() {
            return None;
        }
        let rec = &rest[sp + 1..len];
        let rec = rec.strip_suffix(b"\n").unwrap_or(rec);
        if let Some(v) = rec.strip_prefix(b"path=") {
            return Some(crate::util::escape_bytes(v));
        }
        rest = &rest[len..];
    }
    None
}

/// Read every member. A file over `per_file` bytes, or one that would take
/// the total over `total`, is skipped (its bytes are read past, never kept).
pub fn read_all<R: Read>(r: &mut R, per_file: u64, total: u64) -> Result<Vec<Member>, String> {
    let mut out = Vec::new();
    let mut kept: u64 = 0;
    let mut long_name: Option<String> = None;
    let mut hdr = [0u8; BLOCK];
    loop {
        let n = read_full(r, &mut hdr).map_err(|e| format!("reading the archive: {}", e.kind()))?;
        if n == 0 {
            break; // no end-of-archive blocks: accepted, as GNU tar does with a warning
        }
        if n < BLOCK {
            return Err("the archive ends inside a header".into());
        }
        if hdr.iter().all(|b| *b == 0) {
            break;
        }
        let stored: u64 = hdr[148..156].iter().take_while(|b| **b != 0 && **b != b' ').fold(0, |a, b| a * 8 + (b.wrapping_sub(b'0') as u64));
        let sum: u64 = hdr.iter().enumerate().map(|(i, b)| if (148..156).contains(&i) { b' ' as u64 } else { *b as u64 }).sum();
        if stored != sum {
            return Err("not a tar archive (header checksum mismatch)".into());
        }
        let size = octal(&hdr[124..136])?;
        let typeflag = hdr[156];
        let mut name = cstr(&hdr[0..100]);
        // POSIX ustar only: old GNU headers ("ustar  ") keep times there
        if &hdr[257..263] == b"ustar\0" {
            let prefix = cstr(&hdr[345..500]);
            if !prefix.is_empty() {
                name = format!("{prefix}/{name}");
            }
        }
        match typeflag {
            b'L' | b'x' => {
                if size > 1 << 20 {
                    return Err("an extended header over 1 MB".into());
                }
                let mut data = vec![0u8; size as usize];
                if read_full(r, &mut data).map_err(|e| format!("reading the archive: {}", e.kind()))? < data.len() {
                    return Err("the archive ends inside a member".into());
                }
                skip(r, padding(size)).map_err(|e| e.to_string())?;
                long_name = if typeflag == b'L' { Some(cstr(&data)) } else { pax_path(&data).or(long_name) };
                continue;
            }
            b'g' => {
                skip(r, size + padding(size)).map_err(|e| e.to_string())?;
                continue;
            }
            _ => {}
        }
        if let Some(l) = long_name.take() {
            name = l;
        }
        let what = match typeflag {
            b'0' | 0 | b'7' => None,
            b'5' => Some("directory"),
            b'1' => Some("hard link: not followed"),
            b'2' => Some("symbolic link: not followed"),
            b'3' | b'4' => Some("device node"),
            b'6' => Some("FIFO"),
            _ => Some("member of an unknown type"),
        };
        if let Some(why) = what {
            skip(r, size + padding(size)).map_err(|e| e.to_string())?;
            if typeflag != b'5' {
                out.push(Member::Skipped { name, why: why.into() });
            }
            continue;
        }
        if size > per_file || kept + size > total {
            skip(r, size + padding(size)).map_err(|e| e.to_string())?;
            let why = if size > per_file { format!("{size} bytes, over the {per_file}-byte cap per file") } else { format!("over the {total}-byte cap for the whole import") };
            out.push(Member::Skipped { name, why });
            continue;
        }
        let mut data = vec![0u8; size as usize];
        if read_full(r, &mut data).map_err(|e| format!("reading the archive: {}", e.kind()))? < data.len() {
            return Err("the archive ends inside a member".into());
        }
        skip(r, padding(size)).map_err(|e| e.to_string())?;
        kept += size;
        out.push(Member::File { name, data });
    }
    Ok(out)
}

/// Writes regular files as ustar members, mode 0600, owner 0:0 with no
/// names, mtime fixed by the caller (so the archive says nothing about
/// who packed it)
pub struct Writer<W: Write> {
    w: W,
}

impl<W: Write> Writer<W> {
    pub fn new(w: W) -> Self {
        Writer { w }
    }

    pub fn file(&mut self, name: &str, data: &[u8], mtime: u64) -> io::Result<()> {
        let nb = name.as_bytes();
        let mut hdr = [0u8; BLOCK];
        if nb.len() <= 100 {
            hdr[..nb.len()].copy_from_slice(nb);
        } else {
            // split at a '/' so the prefix holds <= 155 bytes and the name <= 100
            let cut = nb
                .iter()
                .enumerate()
                .filter(|(i, b)| **b == b'/' && *i <= 155 && nb.len() - i - 1 <= 100 && *i > 0)
                .map(|(i, _)| i)
                .next_back()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "a path too long for ustar"))?;
            hdr[345..345 + cut].copy_from_slice(&nb[..cut]);
            hdr[..nb.len() - cut - 1].copy_from_slice(&nb[cut + 1..]);
        }
        let put = |h: &mut [u8; BLOCK], at: usize, len: usize, v: u64| {
            let s = format!("{:0w$o}", v, w = len - 1);
            h[at..at + len - 1].copy_from_slice(s.as_bytes());
        };
        put(&mut hdr, 100, 8, 0o600);
        put(&mut hdr, 108, 8, 0);
        put(&mut hdr, 116, 8, 0);
        put(&mut hdr, 124, 12, data.len() as u64);
        put(&mut hdr, 136, 12, mtime);
        hdr[156] = b'0';
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");
        hdr[148..156].copy_from_slice(b"        ");
        let sum: u64 = hdr.iter().map(|b| *b as u64).sum();
        let s = format!("{:06o}\0 ", sum);
        hdr[148..156].copy_from_slice(s.as_bytes());
        self.w.write_all(&hdr)?;
        self.w.write_all(data)?;
        self.w.write_all(&vec![0u8; padding(data.len() as u64) as usize])
    }

    pub fn finish(mut self) -> io::Result<W> {
        self.w.write_all(&[0u8; BLOCK * 2])?;
        self.w.flush()?;
        Ok(self.w)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_long_names() {
        let long = format!("{}/{}", "d".repeat(120), "f".repeat(90));
        let mut w = Writer::new(Vec::new());
        w.file("a/b.txt", b"hello", 0).unwrap();
        w.file(&long, b"x", 0).unwrap();
        w.file("empty", b"", 0).unwrap();
        let bytes = w.finish().unwrap();
        let ms = read_all(&mut bytes.as_slice(), 1 << 20, 1 << 20).unwrap();
        let got: Vec<(String, Vec<u8>)> = ms
            .into_iter()
            .map(|m| match m {
                Member::File { name, data } => (name, data),
                Member::Skipped { name, why } => panic!("{name}: {why}"),
            })
            .collect();
        assert_eq!(got, vec![("a/b.txt".into(), b"hello".to_vec()), (long, b"x".to_vec()), ("empty".into(), vec![])]);
    }

    #[test]
    fn caps_and_garbage() {
        let mut w = Writer::new(Vec::new());
        w.file("big", &[b'a'; 2000], 0).unwrap();
        w.file("small", b"ok", 0).unwrap();
        let bytes = w.finish().unwrap();
        let ms = read_all(&mut bytes.as_slice(), 1000, 1 << 20).unwrap();
        assert!(matches!(&ms[0], Member::Skipped { name, .. } if name == "big"));
        assert!(matches!(&ms[1], Member::File { name, .. } if name == "small"));
        assert!(read_all(&mut [7u8; 1024].as_slice(), 10, 10).is_err());
    }

    #[test]
    fn gnu_long_name_and_symlink() {
        // hand-built: an 'L' member naming the next, then a symlink
        let mut v = Vec::new();
        let mk = |name: &[u8], size: u64, flag: u8| {
            let mut h = [0u8; BLOCK];
            h[..name.len()].copy_from_slice(name);
            h[124..135].copy_from_slice(format!("{:011o}", size).as_bytes());
            h[156] = flag;
            h[257..263].copy_from_slice(b"ustar ");
            h[148..156].copy_from_slice(b"        ");
            let sum: u64 = h.iter().map(|b| *b as u64).sum();
            h[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
            h
        };
        let ln = b"very/long/name.log\0";
        v.extend_from_slice(&mk(b"././@LongLink", ln.len() as u64, b'L'));
        let mut d = ln.to_vec();
        d.resize(BLOCK, 0);
        v.extend_from_slice(&d);
        v.extend_from_slice(&mk(b"short", 3, b'0'));
        let mut d = b"abc".to_vec();
        d.resize(BLOCK, 0);
        v.extend_from_slice(&d);
        v.extend_from_slice(&mk(b"link", 0, b'2'));
        v.extend_from_slice(&[0u8; BLOCK * 2]);
        let ms = read_all(&mut v.as_slice(), 100, 100).unwrap();
        assert!(matches!(&ms[0], Member::File { name, data } if name == "very/long/name.log" && data == b"abc"));
        assert!(matches!(&ms[1], Member::Skipped { name, .. } if name == "link"));
    }
}
