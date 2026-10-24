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
/// the body is not read at all (rpcprotocol.cpp:276-277)
pub const MAX_BODY: usize = 0x0200_0000;

/// How long Divi Core waits before it refuses wrong credentials
/// (rpcserver.cpp:948-952)
pub const WRONG_CREDENTIALS_DELAY: std::time::Duration = std::time::Duration::from_millis(250);

/// Divi Core's 401 body (rpcprotocol.cpp:91-108)
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

/// Divi Core's HTTPError for 401: "401 Authorization Required", a Basic
/// challenge and an HTML page. Divi Core writes it as HTTP/1.0 and closes the
/// connection; here the close is said with "Connection: close".
pub fn unauthorized() -> Response<Body> {
    let mut res = Response::new(Body::from(UNAUTHORIZED_BODY));
    *res.status_mut() = StatusCode::UNAUTHORIZED;
    *res.version_mut() = Version::HTTP_10;
    res.extensions_mut()
        .insert(hyper::ext::ReasonPhrase::from_static(
            b"Authorization Required",
        ));
    let h = res.headers_mut();
    h.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Basic realm=\"jsonrpc\""),
    );
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static("text/html"));
    h.insert(header::CONNECTION, HeaderValue::from_static("close"));
    res
}

/// Divi Core's HTTPError for another status: the status text as a text/plain
/// body, and the connection closed (rpcprotocol.cpp:109-111)
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
/// with "close" (rpcprotocol.cpp:291-297, rpcserver.cpp:1014-1017)
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

/// The requests Divi Core serves at all: GET or POST (any other method closes
/// the connection unanswered, rpcprotocol.cpp:121-123)
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
    let mut de = serde_json::Deserializer::from_str(text);
    let FirstWins(value) = FirstWins::deserialize(&mut de)?;
    de.end()?;
    Ok(value)
}

struct FirstWins(Value);

impl<'de> Deserialize<'de> for FirstWins {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(FirstWinsVisitor).map(FirstWins)
    }
}

struct FirstWinsVisitor;

impl<'de> Visitor<'de> for FirstWinsVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(FirstWins(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut out = Map::new();
        while let Some((k, FirstWins(v))) = map.next_entry::<String, FirstWins>()? {
            out.entry(k).or_insert(v);
        }
        Ok(Value::Object(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
