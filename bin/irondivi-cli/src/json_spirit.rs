// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! JSON as Divi Core's divi-cli reads and writes it (json_spirit): what an
//! argument parses to, and how a reply is printed. Strings are bytes, object
//! members keep their order, numbers are int, uint64 or real, and a real is
//! always written with 8 decimals.

/// A json_spirit value
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    UInt(u64),
    Real(f64),
    Str(Vec<u8>),
    Array(Vec<Value>),
    Object(Vec<(Vec<u8>, Value)>),
}

impl Value {
    /// json_spirit's name of the value's type, as in "value is type str, expected obj"
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Null => "null",
            Value::Bool(_) => "bool",
            Value::Int(_) | Value::UInt(_) => "int",
            Value::Real(_) => "real",
            Value::Str(_) => "str",
            Value::Array(_) => "array",
            Value::Object(_) => "obj",
        }
    }

    /// The member `key` of an object (json_spirit's find_value: Null if absent)
    pub fn get(&self, key: &str) -> &Value {
        match self {
            Value::Object(members) => members
                .iter()
                .find(|(k, _)| k == key.as_bytes())
                .map(|(_, v)| v)
                .unwrap_or(&Value::Null),
            _ => &Value::Null,
        }
    }
}

/// Parse `text` as json_spirit's read_string does: one value filling the whole
/// text, whitespace around tokens allowed. None if it is not such a value.
pub fn parse(text: &[u8]) -> Option<Value> {
    let mut p = Parser { s: text, i: 0 };
    let value = p.value()?;
    p.ws();
    (p.i == text.len()).then_some(value)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    /// C isspace: space, \t, \n, \v, \f, \r
    fn ws(&mut self) {
        while matches!(
            self.peek(),
            Some(b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
        ) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        self.ws();
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> Option<Value> {
        self.ws();
        match self.peek()? {
            b'"' => self.string().map(Value::Str),
            b'{' => self.object(),
            b'[' => self.array(),
            _ => {
                for (word, value) in [
                    (&b"true"[..], Value::Bool(true)),
                    (b"false", Value::Bool(false)),
                    (b"null", Value::Null),
                ] {
                    if self.s[self.i..].starts_with(word) {
                        self.i += word.len();
                        return Some(value);
                    }
                }
                self.number()
            }
        }
    }

    fn object(&mut self) -> Option<Value> {
        self.i += 1;
        let mut members = Vec::new();
        if self.eat(b'}') {
            return Some(Value::Object(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return None;
            }
            let key = self.string()?;
            if !self.eat(b':') {
                return None;
            }
            members.push((key, self.value()?));
            if self.eat(b',') {
                continue;
            }
            return self.eat(b'}').then_some(Value::Object(members));
        }
    }

    fn array(&mut self) -> Option<Value> {
        self.i += 1;
        let mut items = Vec::new();
        if self.eat(b']') {
            return Some(Value::Array(items));
        }
        loop {
            items.push(self.value()?);
            if self.eat(b',') {
                continue;
            }
            return self.eat(b']').then_some(Value::Array(items));
        }
    }

    /// A quoted string: bytes as they are, escapes replaced; a \u escape
    /// gives one byte (json_spirit keeps a std::string of chars)
    fn string(&mut self) -> Option<Vec<u8>> {
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => return Some(out),
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0c),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => out.push(self.hex(4)? as u8),
                        b'x' => out.push(self.hex(2)? as u8),
                        other => out.push(other),
                    }
                }
                other => out.push(other),
            }
        }
    }

    fn hex(&mut self, digits: usize) -> Option<u32> {
        let text = std::str::from_utf8(self.s.get(self.i..self.i + digits)?).ok()?;
        let value = u32::from_str_radix(text, 16).ok()?;
        self.i += digits;
        Some(value)
    }

    /// Spirit's strict real (a number with a dot or an exponent), else an
    /// int64, else a uint64. A sign may be '+'; leading zeros are accepted.
    fn number(&mut self) -> Option<Value> {
        let start = self.i;
        let digits = |p: &mut Self| {
            let from = p.i;
            while matches!(p.peek(), Some(b'0'..=b'9')) {
                p.i += 1;
            }
            p.i - from
        };
        let signed = matches!(self.peek(), Some(b'+' | b'-'));
        if signed {
            self.i += 1;
        }
        let int_digits = digits(self);
        let mut real = false;
        let mut frac_digits = 0;
        if self.peek() == Some(b'.') {
            let dot = self.i;
            self.i += 1;
            frac_digits = digits(self);
            if int_digits + frac_digits == 0 {
                self.i = dot;
            } else {
                real = true;
            }
        }
        if int_digits + frac_digits == 0 {
            self.i = start;
            return None;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            let e = self.i;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if digits(self) == 0 {
                self.i = e;
            } else {
                real = true;
            }
        }
        let text = std::str::from_utf8(&self.s[start..self.i]).ok()?;
        if real {
            let normal = text.strip_prefix('+').unwrap_or(text);
            return normal.parse::<f64>().ok().map(Value::Real);
        }
        if let Ok(v) = text.strip_prefix('+').unwrap_or(text).parse::<i64>() {
            return Some(Value::Int(v));
        }
        if !text.starts_with('-') {
            if let Ok(v) = text.strip_prefix('+').unwrap_or(text).parse::<u64>() {
                return Some(Value::UInt(v));
            }
        }
        self.i = start;
        None
    }
}

/// Write `value` as json_spirit's write_string: pretty with four-space
/// indents and `"key" : value`, or compact
pub fn write(value: &Value, pretty: bool) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, pretty, 0, &mut out);
    out
}

fn write_value(value: &Value, pretty: bool, level: usize, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Int(i) => out.extend_from_slice(i.to_string().as_bytes()),
        Value::UInt(u) => out.extend_from_slice(u.to_string().as_bytes()),
        // std::showpoint << std::fixed << std::setprecision(8)
        Value::Real(r) => out.extend_from_slice(format!("{:.8}", r).as_bytes()),
        Value::Str(s) => write_string(s, out),
        Value::Array(items) => write_container(
            items.iter().map(|v| (None, v)),
            b'[',
            b']',
            pretty,
            level,
            out,
        ),
        Value::Object(members) => write_container(
            members.iter().map(|(k, v)| (Some(k.as_slice()), v)),
            b'{',
            b'}',
            pretty,
            level,
            out,
        ),
    }
}

fn write_container<'a>(
    items: impl ExactSizeIterator<Item = (Option<&'a [u8]>, &'a Value)>,
    open: u8,
    close: u8,
    pretty: bool,
    level: usize,
    out: &mut Vec<u8>,
) {
    let indent = |level: usize, out: &mut Vec<u8>| {
        if pretty {
            out.extend(std::iter::repeat_n(b' ', 4 * level));
        }
    };
    out.push(open);
    if pretty {
        out.push(b'\n');
    }
    let count = items.len();
    for (n, (key, value)) in items.enumerate() {
        indent(level + 1, out);
        if let Some(key) = key {
            write_string(key, out);
            out.extend_from_slice(if pretty { b" : " } else { b":" });
        }
        write_value(value, pretty, level + 1, out);
        if n + 1 < count {
            out.push(b',');
        }
        if pretty {
            out.push(b'\n');
        }
    }
    indent(level, out);
    out.push(close);
}

/// json_spirit's add_esc_chars: the short escapes, printable ASCII as is, and
/// every other byte as \u00XX (upper-case hex)
fn write_string(s: &[u8], out: &mut Vec<u8>) {
    out.push(b'"');
    for &c in s {
        match c {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0c => out.extend_from_slice(b"\\f"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\t' => out.extend_from_slice(b"\\t"),
            0x20..=0x7e => out.push(c),
            _ => out.extend_from_slice(format!("\\u{:04X}", c).as_bytes()),
        }
    }
    out.push(b'"');
}

/// The value as serde JSON for the request body (strings as UTF-8, reals
/// rounded to 8 decimals as divi-cli sends them)
pub fn to_serde(value: &Value) -> serde_json::Value {
    use serde_json::Value as J;
    match value {
        Value::Null => J::Null,
        Value::Bool(b) => J::Bool(*b),
        Value::Int(i) => J::from(*i),
        Value::UInt(u) => J::from(*u),
        Value::Real(r) => {
            let rounded: f64 = format!("{:.8}", r).parse().unwrap_or(*r);
            serde_json::Number::from_f64(rounded).map_or(J::Null, J::Number)
        }
        Value::Str(s) => J::String(String::from_utf8_lossy(s).into_owned()),
        Value::Array(items) => J::Array(items.iter().map(to_serde).collect()),
        Value::Object(members) => J::Object(
            members
                .iter()
                .map(|(k, v)| (String::from_utf8_lossy(k).into_owned(), to_serde(v)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<Value> {
        parse(s.as_bytes())
    }

    /// What Divi Core 3.0.0's divi-cli sent for each argument (probed against
    /// a recording server): a value when the whole argument is JSON, else the
    /// argument as a string
    #[test]
    fn arguments_parse_as_divi_cli_reads_them() {
        assert_eq!(p("1234"), Some(Value::Int(1234)));
        assert_eq!(p("true"), Some(Value::Bool(true)));
        assert_eq!(p("1.5"), Some(Value::Real(1.5)));
        assert_eq!(p("1e3"), Some(Value::Real(1000.0)));
        assert_eq!(p("-0"), Some(Value::Int(0)));
        assert_eq!(p("null"), Some(Value::Null));
        assert_eq!(p(" 1"), Some(Value::Int(1)));
        assert_eq!(p("1 "), Some(Value::Int(1)));
        assert_eq!(p("01"), Some(Value::Int(1)));
        assert_eq!(p("+1"), Some(Value::Int(1)));
        assert_eq!(p(".5"), Some(Value::Real(0.5)));
        assert_eq!(p("1."), Some(Value::Real(1.0)));
        assert_eq!(
            p("12345678901234567890"),
            Some(Value::UInt(12345678901234567890))
        );
        for s in ["abc", "8nrmPV", "1abc", "0x10", "{bad", "tRue", "", "1 2"] {
            assert_eq!(p(s), None, "{s:?}");
        }
        assert_eq!(
            p("{\"a\":[1,{}],\"b\":\"x\"}"),
            Some(Value::Object(vec![
                (
                    b"a".to_vec(),
                    Value::Array(vec![Value::Int(1), Value::Object(vec![])])
                ),
                (b"b".to_vec(), Value::Str(b"x".to_vec())),
            ]))
        );
    }

    /// The reply printed as divi-cli printed it for the same reply body
    #[test]
    fn pretty_output_is_divi_cli_s() {
        let reply = br#"{"b":1,"a":[1,2.5,"x",{}],"c":{"d":null,"e":[]},"f":0.1,"g":1e-9,"h":"\u0001\t\"/"}"#;
        let v = parse(reply).unwrap();
        let expected = "{\n    \"b\" : 1,\n    \"a\" : [\n        1,\n        2.50000000,\n        \"x\",\n        {\n        }\n    ],\n    \"c\" : {\n        \"d\" : null,\n        \"e\" : [\n        ]\n    },\n    \"f\" : 0.10000000,\n    \"g\" : 0.00000000,\n    \"h\" : \"\\u0001\\t\\\"/\"\n}";
        assert_eq!(String::from_utf8(write(&v, true)).unwrap(), expected);
        // Non-ASCII bytes are escaped one by one
        let v = parse("\"\u{e9}\"".as_bytes()).unwrap();
        assert_eq!(write(&v, true), b"\"\\u00C3\\u00A9\"");
        assert_eq!(
            String::from_utf8(write(
                &parse(br#"{"code":-5,"message":"Invalid address"}"#).unwrap(),
                false
            ))
            .unwrap(),
            r#"{"code":-5,"message":"Invalid address"}"#
        );
    }
}
