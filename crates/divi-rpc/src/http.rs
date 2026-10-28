// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The HTTP side of the RPC server as Divi Core 3.0.0 has it (rpcprotocol.cpp,
//! rpcserver.cpp ServiceConnection / HTTPReq_JSONRPC): its replies outside
//! JSON-RPC, its keep-alive rule, its body size limit and its JSON reading.

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Method, Response, StatusCode, Version},
};
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

/// The most request body Divi Core reads (MAX_SIZE, serialize.h:34); above it
/// the body is not read at all (rpcprotocol.cpp:218-220)
pub const MAX_BODY: usize = 0x0200_0000;

/// How long Divi Core waits before it refuses wrong credentials
/// (rpcserver.cpp:948-952)
pub const WRONG_CREDENTIALS_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Divi Core's 401 body (rpcprotocol.cpp:85-105)
const UNAUTHORIZED_BODY: &str =
    "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\"\r\n\
\"http://www.w3.org/TR/1999/REC-html401-19991224/loose.dtd\">\r\n\
<HTML>\r\n\
<HEAD>\r\n\
<TITLE>Error</TITLE>\r\n\
<META HTTP-EQUIV='Content-Type' CONTENT='text/html; charset=ISO-8859-1'>\r\n\
</HEAD>\r\n\
<BODY><H1>401 Unauthorized.</H1></BODY>\r\n\
</HTML>\r\n";

/// A reply hyper does not write: the RPC server's connection (server.rs,
/// `serve_listener`) writes these bytes as they are, or nothing at all when
/// there are none, and closes. Divi Core writes some replies its own way,
/// which hyper's rules would change: a 401 with no Connection header
/// followed by the close.
#[derive(Clone, Debug)]
pub struct RawReply(pub Option<Vec<u8>>);

/// Divi Core's HTTPError for 401: "401 Authorization Required" as HTTP/1.0, a
/// Basic challenge and an HTML page, with no Connection header, and the
/// connection closed after it (rpcprotocol.cpp:85-105, rpcserver.cpp:1020-1022).
/// hyper would add "connection: close" to a reply on a connection it means to
/// close, so the bytes go out as a [`RawReply`]; the response itself is what
/// a caller of the router sees. No Server line: irondivid sends none.
pub fn unauthorized() -> Response<Body> {
    let mut res = Response::new(Body::from(UNAUTHORIZED_BODY));
    *res.status_mut() = StatusCode::UNAUTHORIZED;
    *res.version_mut() = Version::HTTP_10;
    res.extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            b"Authorization Required",
        ));
    let date = chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S +0000");
    let raw = format!(
        "HTTP/1.0 401 Authorization Required\r\n\
         Date: {date}\r\n\
         WWW-Authenticate: Basic realm=\"jsonrpc\"\r\n\
         Content-Type: text/html\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {UNAUTHORIZED_BODY}",
        UNAUTHORIZED_BODY.len()
    );
    res.extensions_mut()
        .insert(RawReply(Some(raw.into_bytes())));
    let h = res.headers_mut();
    h.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"jsonrpc\""),
    );
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    res
}

/// Divi Core's HTTPError for another status: the status text as a text/plain
/// body, and the connection closed (rpcprotocol.cpp:106-108)
pub fn error_page(status: StatusCode) -> Response<Body> {
    let text = status.canonical_reason().unwrap_or("");
    let mut res = Response::new(Body::from(text));
    *res.status_mut() = status;
    let h = res.headers_mut();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    h.insert(header::CONNECTION, HeaderValue::from_static("close"));
    res
}

/// Whether Divi Core keeps the connection after a reply to this request: a
/// "Connection" of "keep-alive", or none (or another value) on HTTP/1.1; never
/// with "close" (rpcprotocol.cpp:239-245, rpcserver.cpp:1014-1017)
pub fn keep_alive(version: Version, headers: &HeaderMap) -> bool {
    match headers
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
    {
        Some("close") => false,
        Some("keep-alive") => true,
        _ => version != Version::HTTP_10 && version != Version::HTTP_09,
    }
}

/// The Connection header of a JSON-RPC reply: an error reply always closes the
/// connection (ErrorReply, rpcserver.cpp:500-511), a 200 follows `keep_alive`
pub fn connection_header(status: StatusCode, keep: bool) -> HeaderValue {
    HeaderValue::from_static(if status == StatusCode::OK && keep {
        "keep-alive"
    } else {
        "close"
    })
}

/// What Divi Core answers a request it does not read: nothing, the connection
/// closed (ReadHTTPRequestLine fails and ServiceConnection ends,
/// rpcprotocol.cpp:150-157, rpcserver.cpp:1009-1010). The connection writes
/// nothing ([`RawReply`]); a caller of the router sees a 400 with no body.
pub fn no_reply() -> Response<Body> {
    let mut res = Response::new(Body::empty());
    *res.status_mut() = StatusCode::BAD_REQUEST;
    res.extensions_mut().insert(RawReply(None));
    res
}

/// The requests Divi Core serves at all: GET or POST, as written (any other
/// method closes the connection unanswered, rpcprotocol.cpp:150-152)
pub fn method_served(method: &Method) -> bool {
    method == Method::GET || method == Method::POST
}

/// A declared body larger than Divi Core reads
pub fn body_too_large(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .is_some_and(|n| n > MAX_BODY as u64)
}

/// Parse JSON as Divi Core's json_spirit finds members: when a key appears
/// twice in an object, the first one counts (find_value takes the first match)
pub fn parse_json(text: &str) -> Result<Value, serde_json::Error> {
    parse_json_members(text).map(|j| j.first_wins())
}

/// Parse JSON keeping every member of each object in order, as json_spirit's
/// Object (a vector of pairs) holds them, equal keys included
pub fn parse_json_members(text: &str) -> Result<Json, serde_json::Error> {
    let numbers = numbers_as_json_spirit(text).ok_or_else(|| {
        <serde_json::Error as serde::de::Error>::custom("integer out of int64 and uint64 range")
    })?;
    let text = numbers.as_deref().unwrap_or(text);
    let mut de = serde_json::Deserializer::from_str(text);
    let value = Json::deserialize(&mut de)?;
    de.end()?;
    Ok(value)
}

/// The text with each number outside strings read as json_spirit reads it
/// (json_spirit_reader_template.h:498-501: Spirit's strict real, else an
/// int64, else a uint64) and written as serde_json reads the same value:
/// - a number with a dot or an exponent is a real, "1." and ".5" too;
/// - any other is an integer: "+5" and "05" are 5, "-0" is 0, and one that
///   fits neither int64 nor uint64 makes the whole request a parse error
///   (`None`), where serde_json would read it as a real.
///
/// `Some(None)` leaves the text as it is. A token that is no number, or a real
/// beyond f64 (json_spirit's infinity, which serde_json has no value for), is
/// left for serde_json to refuse.
pub fn numbers_as_json_spirit(text: &str) -> Option<Option<String>> {
    let b = text.as_bytes();
    let mut out = String::new();
    let mut copied = 0;
    let mut in_string = false;
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if in_string {
            match c {
                b'\\' => i += 2,
                b'"' => {
                    in_string = false;
                    i += 1;
                }
                _ => i += 1,
            }
            continue;
        }
        if c == b'"' {
            in_string = true;
            i += 1;
            continue;
        }
        if !matches!(c, b'0'..=b'9' | b'+' | b'-' | b'.') {
            i += 1;
            continue;
        }
        let Some((end, value)) = json_spirit_number(b, i) else {
            i += 1;
            continue;
        };
        let token = &text[i..end];
        let written = match value {
            Number::Int(v) => v.to_string(),
            Number::UInt(v) => v.to_string(),
            Number::Real(v) if v.is_finite() => format!("{v:e}"),
            Number::Real(_) => token.to_string(),
            Number::OutOfRange => return None,
        };
        if written != token {
            out.push_str(&text[copied..i]);
            out.push_str(&written);
            copied = end;
        }
        i = end;
    }
    if copied == 0 {
        return Some(None);
    }
    out.push_str(&text[copied..]);
    Some(Some(out))
}

enum Number {
    Int(i64),
    UInt(u64),
    Real(f64),
    OutOfRange,
}

/// The number json_spirit reads at `start`, and where it ends: an optional
/// sign, digits with an optional dot (digits on at least one side of it), an
/// optional exponent. `None` when there is no number there.
fn json_spirit_number(b: &[u8], start: usize) -> Option<(usize, Number)> {
    let digits = |from: usize| {
        (from..b.len())
            .find(|&k| !b[k].is_ascii_digit())
            .unwrap_or(b.len())
    };
    let mut i = start;
    if matches!(b[i], b'+' | b'-') {
        i += 1;
    }
    let int_end = digits(i);
    let int_digits = int_end - i;
    i = int_end;
    let mut real = false;
    if b.get(i) == Some(&b'.') {
        let frac_end = digits(i + 1);
        if int_digits + (frac_end - i - 1) > 0 {
            real = true;
            i = frac_end;
        }
    }
    if int_digits == 0 && !real {
        return None;
    }
    if matches!(b.get(i), Some(b'e' | b'E')) {
        let mut e = i + 1;
        if matches!(b.get(e), Some(b'+' | b'-')) {
            e += 1;
        }
        let exp_end = digits(e);
        if exp_end > e {
            real = true;
            i = exp_end;
        }
    }
    let token = std::str::from_utf8(&b[start..i]).ok()?;
    let unsigned = token.strip_prefix('+').unwrap_or(token);
    let value = if real {
        Number::Real(unsigned.parse::<f64>().ok()?)
    } else if let Ok(v) = unsigned.parse::<i64>() {
        Number::Int(v)
    } else {
        match unsigned.parse::<u64>() {
            Ok(v) if !token.starts_with('-') => Number::UInt(v),
            _ => Number::OutOfRange,
        }
    };
    Some((i, value))
}

/// A JSON value whose objects keep all their members, equal keys included
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// Anything but an array or object
    Scalar(Value),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    /// The value as json_spirit's find_value reads it: of equal keys the first
    pub fn first_wins(&self) -> Value {
        match self {
            Json::Scalar(v) => v.clone(),
            Json::Array(items) => Value::Array(items.iter().map(Json::first_wins).collect()),
            Json::Object(members) => {
                let mut out = Map::new();
                for (k, v) in members {
                    out.entry(k.clone()).or_insert_with(|| v.first_wins());
                }
                Value::Object(out)
            }
        }
    }

    /// The first member named `key` of an object
    pub fn member(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Element `index` of an array
    pub fn element(&self, index: usize) -> Option<&Json> {
        match self {
            Json::Array(items) => items.get(index),
            _ => None,
        }
    }

    /// Every member of an object, in order, each value read first-wins
    pub fn members(&self) -> Option<Vec<(String, Value)>> {
        match self {
            Json::Object(members) => Some(
                members
                    .iter()
                    .map(|(k, v)| (k.clone(), v.first_wins()))
                    .collect(),
            ),
            _ => None,
        }
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(JsonVisitor)
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Json, E> {
        Ok(Json::Scalar(Value::Bool(v)))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Json, E> {
        Ok(Json::Scalar(Value::from(v)))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Json, E> {
        Ok(Json::Scalar(Value::from(v)))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Json, E> {
        Ok(Json::Scalar(
            serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number),
        ))
    }

    fn visit_str<E>(self, v: &str) -> Result<Json, E> {
        Ok(Json::Scalar(Value::String(v.to_string())))
    }

    fn visit_string<E>(self, v: String) -> Result<Json, E> {
        Ok(Json::Scalar(Value::String(v)))
    }

    fn visit_unit<E>(self) -> Result<Json, E> {
        Ok(Json::Scalar(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Json, E> {
        Ok(Json::Scalar(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element()? {
            out.push(v);
        }
        Ok(Json::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut out = Vec::new();
        while let Some(entry) = map.next_entry::<String, Json>()? {
            out.push(entry);
        }
        Ok(Json::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn json_keeps_the_first_of_two_equal_keys() {
        let v = parse_json(r#"{"method":"a","method":"b","x":{"k":1,"k":2},"l":[{"m":1,"m":2}]}"#)
            .unwrap();
        assert_eq!(v["method"], "a");
        assert_eq!(v["x"]["k"], 1);
        assert_eq!(v["l"][0]["m"], 1);
        assert_eq!(parse_json("1.5").unwrap(), serde_json::json!(1.5));
        assert_eq!(parse_json(" [] ").unwrap(), serde_json::json!([]));
        assert!(parse_json("{bad").is_err());
        assert!(parse_json(r#"{"a":1}x"#).is_err());
    }

    #[test]
    fn numbers_are_read_as_json_spirit_reads_them() {
        let one = |n: &str| parse_json(&format!("[{n}]")).map(|v| v[0].clone());
        // json_spirit has no value for an integer outside int64 and uint64:
        // the request is a parse error, not a real
        assert!(one("18446744073709551616").is_err());
        assert!(one("-9223372036854775809").is_err());
        assert!(one("100000000000000000000000").is_err());
        assert_eq!(one("18446744073709551615").unwrap(), json!(u64::MAX));
        assert_eq!(one("-9223372036854775808").unwrap(), json!(i64::MIN));
        // A sign of '+' and leading zeros are an integer; "-0" is 0
        assert_eq!(one("+5").unwrap(), json!(5));
        assert_eq!(one("05").unwrap(), json!(5));
        assert_eq!(one("-0").unwrap(), json!(0));
        assert!(one("-0").unwrap().is_i64());
        // A dot or an exponent is a real, with digits on one side of the dot
        assert_eq!(one("1.").unwrap(), json!(1.0));
        assert_eq!(one(".5").unwrap(), json!(0.5));
        assert_eq!(one("-.5").unwrap(), json!(-0.5));
        assert_eq!(one("1e5").unwrap(), json!(100000.0));
        assert_eq!(one("1E+2").unwrap(), json!(100.0));
        assert_eq!(one("0.1").unwrap(), json!(0.1));
        assert_eq!(one("123456.789e-3").unwrap(), json!(123.456789));
        // Not numbers
        for bad in ["-", "+", ".", "1e", "5x", "0x10", "--1"] {
            assert!(one(bad).is_err(), "{bad}");
        }
        // Text in strings is left alone, escaped quotes included
        assert_eq!(
            parse_json(r#"["+5 \" 05", -0, {"k": "1."}]"#).unwrap(),
            json!(["+5 \" 05", 0, {"k": "1."}])
        );
    }

    #[test]
    fn json_members_keep_equal_keys() {
        let j = parse_json_members(r#"{"params":["",{"a":1,"b":2,"a":{"x":1,"x":2}}]}"#).unwrap();
        let amounts = j.member("params").and_then(|p| p.element(1)).unwrap();
        assert_eq!(
            amounts.members().unwrap(),
            vec![
                ("a".to_string(), serde_json::json!(1)),
                ("b".to_string(), serde_json::json!(2)),
                ("a".to_string(), serde_json::json!({"x": 1})),
            ]
        );
    }

    #[test]
    fn keep_alive_follows_divid_s_rule() {
        let with = |v: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::CONNECTION, HeaderValue::from_str(v).unwrap());
            h
        };
        let none = HeaderMap::new();
        assert!(keep_alive(Version::HTTP_11, &none));
        assert!(!keep_alive(Version::HTTP_10, &none));
        assert!(keep_alive(Version::HTTP_10, &with("keep-alive")));
        assert!(!keep_alive(Version::HTTP_11, &with("close")));
        // Divi Core compares the value as written
        assert!(keep_alive(Version::HTTP_11, &with("Close")));
        assert_eq!(connection_header(StatusCode::OK, true), "keep-alive");
        assert_eq!(connection_header(StatusCode::NOT_FOUND, true), "close");
    }

    #[test]
    fn body_limit_is_divid_s_max_size() {
        let len = |n: u64| {
            let mut h = HeaderMap::new();
            h.insert(header::CONTENT_LENGTH, HeaderValue::from(n));
            h
        };
        assert!(!body_too_large(&len(MAX_BODY as u64)));
        assert!(body_too_large(&len(MAX_BODY as u64 + 1)));
        assert!(!body_too_large(&HeaderMap::new()));
    }
}
