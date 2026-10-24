// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Text in requests as Divi Core's json_spirit reads it.
//!
//! divi-cli writes each byte of a non-ASCII argument as its own `\u00XX` escape
//! ("ü" is `Ã¼`), and divid's json_spirit reads a `\uHHHH` escape back
//! into one byte, its low 8 bits (json_spirit_reader_template.h:71-82, :111-117),
//! so the UTF-8 text comes back whole. serde_json reads each escape as a code
//! point, which turns divi-cli's "ü" into "Ã¼".

/// The request body with each `\u00XX` escape (XX of 80 or more) inside its
/// strings written as the byte it names, when that is how divid would read it:
/// every `\u` escape is below 0x100 and the bytes make valid UTF-8. `None`
/// leaves the body as it is (no such escape, an escape of a code point beyond
/// one byte, or bytes that are no UTF-8 text, as a client writes when it
/// escapes code points).
pub fn byte_escapes_as_divid(body: &str) -> Option<String> {
    let bytes = body.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut in_string = false;
    let mut changed = false;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if !in_string {
            in_string = b == b'"';
            out.push(b);
            i += 1;
            continue;
        }
        match b {
            b'"' => {
                in_string = false;
                out.push(b);
                i += 1;
            }
            b'\\' if bytes.get(i + 1) == Some(&b'u') => {
                let hex = body.get(i + 2..i + 6)?;
                let value = u32::from_str_radix(hex, 16).ok()?;
                if value >= 0x100 {
                    return None;
                }
                if value >= 0x80 {
                    out.push(value as u8);
                    changed = true;
                } else {
                    out.extend_from_slice(&bytes[i..i + 6]);
                }
                i += 6;
            }
            b'\\' => {
                // any other escape is kept as written, with the character it escapes
                out.extend_from_slice(bytes.get(i..i + 2)?);
                i += 2;
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }
    if !changed {
        return None;
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divi_clis_byte_escapes_become_the_text() {
        let sent = r#"{"method":"setaccount","params":["y","Z\u00C3\u00BCrich \u00E2\u009C\u0093"],"id":1}"#;
        let read = byte_escapes_as_divid(sent).unwrap();
        let v: serde_json::Value = serde_json::from_str(&read).unwrap();
        assert_eq!(v["params"][1], "Z\u{fc}rich \u{2713}");
    }

    #[test]
    fn other_bodies_are_left_alone() {
        // no escape of a high byte
        assert_eq!(
            byte_escapes_as_divid(r#"{"a":"plain \n \" \u0041 \\u00C3"}"#),
            None
        );
        // raw UTF-8, as irondivi-cli sends it
        assert_eq!(byte_escapes_as_divid("{\"a\":\"Z\u{fc}rich\"}"), None);
        // a code point escape, as a client escaping characters sends it
        assert_eq!(byte_escapes_as_divid(r#"{"a":"\u2713"}"#), None);
        // one high byte alone is no UTF-8 (a code point escaped as such)
        assert_eq!(byte_escapes_as_divid(r#"{"a":"Z\u00fcrich"}"#), None);
        // a cut-off escape is left to the parser
        assert_eq!(byte_escapes_as_divid(r#"{"a":"\u00C"#), None);
    }

    #[test]
    fn low_escapes_stay_escaped_next_to_high_ones() {
        let read = byte_escapes_as_divid(r#"["\u0022\u00C3\u00BC\u000a"]"#).unwrap();
        let v: serde_json::Value = serde_json::from_str(&read).unwrap();
        assert_eq!(v[0], "\"\u{fc}\n");
    }
}
