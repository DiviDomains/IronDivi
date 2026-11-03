// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! The binary's build-id (diag plan A16), read once at start from the
//! loaded image: the ELF `NT_GNU_BUILD_ID` note on Linux and FreeBSD, the
//! Mach-O `LC_UUID` on macOS. Lowercase hex, `-` when there is none.
//!
//! runs.log's `start` record and every crash.log entry name it, so a crash
//! resolves against the unstripped binary `tools/release-symbols.sh` keeps
//! under the same id. [`get`] is one atomic load and allocates nothing: the
//! fatal-signal handler calls it.

use std::sync::OnceLock;

static ID: OnceLock<String> = OnceLock::new();

/// Read the build-id; first thing in main, before any thread
pub fn init() {
    let _ = ID.set(read().unwrap_or_else(|| "-".to_string()));
}

/// The build-id, `-` before [`init`] or when the binary has none
pub fn get() -> &'static str {
    ID.get().map_or("-", |s| s.as_str())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// The `NT_GNU_BUILD_ID` descriptor among ELF notes, in the build's own
/// byte order
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android", target_os = "freebsd")),
    allow(dead_code)
)]
fn gnu_build_id(notes: &[u8]) -> Option<String> {
    const NT_GNU_BUILD_ID: usize = 3;
    let word = |i: usize| {
        notes
            .get(i..i.checked_add(4)?)
            .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let align = |n: usize| n.checked_add(3).map(|n| n & !3);
    let mut at = 0;
    while let (Some(namesz), Some(descsz), Some(kind)) = (word(at), word(at + 4), word(at + 8)) {
        let name_at = at + 12;
        let desc_at = name_at.checked_add(align(namesz)?)?;
        let next = desc_at.checked_add(align(descsz)?)?;
        if kind == NT_GNU_BUILD_ID
            && descsz > 0
            && notes.get(name_at..name_at + namesz) == Some(&b"GNU\0"[..])
        {
            return notes.get(desc_at..desc_at.checked_add(descsz)?).map(hex);
        }
        at = next;
    }
    None
}

/// The executable is the first object `dl_iterate_phdr` reports
#[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
fn read() -> Option<String> {
    const PT_NOTE: u32 = 4;
    unsafe extern "C" fn first(
        info: *mut libc::dl_phdr_info,
        _size: libc::size_t,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let out = unsafe { &mut *(data as *mut Option<String>) };
        let info = unsafe { &*info };
        if !info.dlpi_phdr.is_null() {
            let headers =
                unsafe { std::slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize) };
            for h in headers.iter().filter(|h| h.p_type == PT_NOTE) {
                let at = (info.dlpi_addr as usize).wrapping_add(h.p_vaddr as usize);
                let notes =
                    unsafe { std::slice::from_raw_parts(at as *const u8, h.p_memsz as usize) };
                if let Some(id) = gnu_build_id(notes) {
                    *out = Some(id);
                    break;
                }
            }
        }
        1
    }
    let mut out: Option<String> = None;
    unsafe { libc::dl_iterate_phdr(Some(first), (&mut out as *mut Option<String>).cast()) };
    out
}

/// `LC_UUID` from the main image's load commands (64-bit Mach-O)
#[cfg(target_vendor = "apple")]
fn read() -> Option<String> {
    extern "C" {
        fn _dyld_get_image_header(image_index: u32) -> *const u8;
    }
    const LC_UUID: u32 = 0x1b;
    const HEADER: usize = 32;
    let header = unsafe { _dyld_get_image_header(0) };
    if header.is_null() {
        return None;
    }
    let word = |p: *const u8| unsafe { std::ptr::read_unaligned(p as *const u32) };
    let ncmds = word(unsafe { header.add(16) });
    let mut p = unsafe { header.add(HEADER) };
    for _ in 0..ncmds {
        let (cmd, size) = (word(p), word(unsafe { p.add(4) }) as usize);
        if cmd == LC_UUID && size >= 24 {
            return Some(hex(unsafe { std::slice::from_raw_parts(p.add(8), 16) }));
        }
        if size == 0 {
            return None;
        }
        p = unsafe { p.add(size) };
    }
    None
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_vendor = "apple"
)))]
fn read() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(name: &[u8], kind: u32, desc: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&(name.len() as u32).to_ne_bytes());
        v.extend_from_slice(&(desc.len() as u32).to_ne_bytes());
        v.extend_from_slice(&kind.to_ne_bytes());
        v.extend_from_slice(name);
        v.resize(v.len().div_ceil(4) * 4, 0);
        v.extend_from_slice(desc);
        v.resize(v.len().div_ceil(4) * 4, 0);
        v
    }

    #[test]
    fn the_gnu_build_id_note_is_found_among_others() {
        let mut notes = note(b"GNU\0", 1, &[0; 16]); // NT_GNU_ABI_TAG
        notes.extend(note(b"FreeBSD\0", 3, &[1, 2, 3]));
        notes.extend(note(b"GNU\0", 3, &[0xab, 0x01, 0xff]));
        assert_eq!(gnu_build_id(&notes).as_deref(), Some("ab01ff"));
        assert_eq!(gnu_build_id(&notes[..notes.len() - 4]), None, "cut short");
        assert_eq!(gnu_build_id(&[]), None);
    }

    /// The test binary is linked like the node: it carries a build-id
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn the_running_binary_has_a_build_id() {
        let id = read().expect("no build-id in the test binary");
        assert!(
            id.len() >= 32 && id.bytes().all(|b| b.is_ascii_hexdigit()),
            "{}",
            id
        );
        init();
        assert_eq!(get(), id);
        // The same id readelf finds in the file, where readelf is installed
        #[cfg(target_os = "linux")]
        if let Ok(out) = std::process::Command::new("readelf")
            .arg("-n")
            .arg(std::env::current_exe().unwrap())
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            assert!(text.contains(&format!("Build ID: {}", id)), "{}", text);
        }
    }
}
