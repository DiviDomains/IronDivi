// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! Read and change the config file as irondivid reads it: TOML when the file
//! is irondivid's own (`irondivi.conf` or `*.toml`) and parses as TOML, else
//! divid's `name=value` lines. An edit keeps every other line and comment,
//! is checked by reading the new text back, keeps the old file as `.bak`, and
//! replaces the file whole.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Each option the file sets, with every value in the file's order
pub type Values = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Divi,
    Toml,
}

/// The file is irondivid's own, which may be TOML
fn own(path: &Path) -> bool {
    path.file_name().is_some_and(|n| n == "irondivi.conf")
        || path.extension().is_some_and(|e| e == "toml")
}

/// How irondivid reads `content` at `path`
pub fn format_of(path: &Path, content: Option<&str>) -> Format {
    match content {
        Some(text) if own(path) && text.parse::<toml_edit::DocumentMut>().is_ok() => Format::Toml,
        Some(_) => Format::Divi,
        None if own(path) => Format::Toml,
        None => Format::Divi,
    }
}

/// Divi Core's InterpretBool as irondivid has it
fn interpret_bool(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    let v = value.trim_start();
    let digits = v.strip_prefix(['-', '+']).unwrap_or(v);
    let end = digits
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(digits.len());
    digits[..end].parse::<i64>().unwrap_or(0) != 0
}

/// `-nofoo=v` is `foo=!v` (irondivid's Settings::set)
fn add(values: &mut Values, key: &str, value: &str) {
    let (key, value) = match key.strip_prefix("no") {
        Some(rest) if key.len() > 2 => (
            rest.to_string(),
            if interpret_bool(value) { "0" } else { "1" }.to_string(),
        ),
        _ => (key.to_string(), value.to_string()),
    };
    values.entry(key).or_default().push(value);
}

/// A divi-format line's option name as irondivid takes it (the section and
/// any `net.` prefix dropped, a single leading dash cut), without the `no`
/// handling; None for a line that sets nothing
fn divi_key(section: Option<&str>, key: &str) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let full = match section {
        Some(s) if !s.is_empty() => format!("{s}.{key}"),
        _ => key.to_string(),
    };
    let key = match full.split_once('.') {
        Some((net, rest)) if !net.is_empty() => rest.to_string(),
        _ => full,
    };
    match key.strip_prefix('-') {
        Some(rest) if rest.starts_with('-') => None,
        Some(rest) => Some(rest.to_string()),
        None => Some(key),
    }
}

/// The option a name sets, `no` cut
fn base_key(key: &str) -> &str {
    match key.strip_prefix("no") {
        Some(rest) if key.len() > 2 => rest,
        _ => key,
    }
}

/// What irondivid reads from a divi-format file
fn read_divi(content: &str) -> Result<Values, String> {
    let mut values = Values::new();
    let mut section: Option<String> = None;
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = Some(line[1..line.len() - 1].trim().to_string());
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            return Err(format!(
                "the options configuration file contains an invalid line '{line}'"
            ));
        };
        if let Some(key) = divi_key(section.as_deref(), k.trim()) {
            add(&mut values, &key, v.trim());
        }
    }
    Ok(values)
}

/// What irondivid reads from a TOML file: its top-level keys
fn read_toml(doc: &toml_edit::DocumentMut) -> Values {
    let mut values = Values::new();
    for (key, item) in doc.iter() {
        let Some(value) = item.as_value() else {
            continue;
        };
        let list: Vec<&toml_edit::Value> = match value.as_array() {
            Some(a) => a.iter().collect(),
            None => vec![value],
        };
        for v in list {
            let text = match v {
                toml_edit::Value::String(s) => s.value().clone(),
                toml_edit::Value::Integer(i) => i.value().to_string(),
                toml_edit::Value::Float(f) => f.value().to_string(),
                toml_edit::Value::Boolean(b) => if *b.value() { "1" } else { "0" }.to_string(),
                _ => continue,
            };
            add(&mut values, key, &text);
        }
    }
    values
}

/// What irondivid reads from `content` at `path`
pub fn read_values(path: &Path, content: &str) -> Result<Values, String> {
    match format_of(path, Some(content)) {
        Format::Toml => content
            .parse::<toml_edit::DocumentMut>()
            .map(|d| read_toml(&d))
            .map_err(|e| e.to_string()),
        Format::Divi => read_divi(content),
    }
}

/// The values the file sets now; empty when there is no file
pub fn read_file(path: &Path) -> Result<Values, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => read_values(path, &text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Values::new()),
        Err(e) => Err(format!("cannot read {}: {}", path.display(), e)),
    }
}

/// How a TOML value is written for an option
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TomlType {
    Bool,
    Int,
    Str,
}

/// One change: the option, its new values (None removes it), how TOML
/// writes it, and whether it may repeat
#[derive(Debug, Clone)]
pub struct Change {
    pub key: String,
    pub values: Option<Vec<String>>,
    pub toml: TomlType,
    pub multi: bool,
}

fn edit_divi(content: &str, changes: &[Change]) -> Result<String, String> {
    for c in changes {
        for v in c.values.iter().flatten() {
            if v.contains('#') {
                return Err(format!(
                    "{}: divi.conf cannot hold '#' in a value (it starts a comment)",
                    c.key
                ));
            }
        }
    }
    let lines: Vec<&str> = content.lines().collect();
    // Which change each line sets, if any
    let mut owner: Vec<Option<usize>> = vec![None; lines.len()];
    let mut first_section: Option<usize> = None;
    let mut section: Option<String> = None;
    for (i, raw) in lines.iter().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') && line.ends_with(']') {
            first_section.get_or_insert(i);
            section = Some(line[1..line.len() - 1].trim().to_string());
            continue;
        }
        let Some((k, _)) = line.split_once('=') else {
            continue;
        };
        if let Some(key) = divi_key(section.as_deref(), k.trim()) {
            owner[i] = changes.iter().position(|c| c.key == base_key(&key));
        }
    }
    let new_lines = |c: &Change| -> Vec<String> {
        c.values
            .iter()
            .flatten()
            .map(|v| format!("{}={}", c.key, v))
            .collect()
    };
    let mut out: Vec<String> = Vec::new();
    let mut placed = vec![false; changes.len()];
    for (i, raw) in lines.iter().enumerate() {
        if first_section == Some(i) {
            for (n, c) in changes.iter().enumerate() {
                if !placed[n] && !owner.contains(&Some(n)) {
                    out.extend(new_lines(c));
                    placed[n] = true;
                }
            }
        }
        match owner[i] {
            Some(n) => {
                // The line goes; a comment on it stays on a line of its own
                if let Some((_, comment)) = raw.split_once('#') {
                    if !comment.trim().is_empty() {
                        out.push(format!("#{comment}"));
                    }
                }
                if !placed[n] {
                    out.extend(new_lines(&changes[n]));
                    placed[n] = true;
                }
            }
            None => out.push(raw.to_string()),
        }
    }
    for (n, c) in changes.iter().enumerate() {
        if !placed[n] {
            out.extend(new_lines(c));
        }
    }
    let mut text = out.join("\n");
    if !text.is_empty() {
        text.push('\n');
    }
    Ok(text)
}

fn toml_value(c: &Change, v: &str) -> Result<toml_edit::Value, String> {
    Ok(match c.toml {
        TomlType::Bool => toml_edit::Value::from(v == "1"),
        TomlType::Int => toml_edit::Value::from(
            v.parse::<i64>()
                .map_err(|_| format!("{}: not a number", c.key))?,
        ),
        TomlType::Str => toml_edit::Value::from(v),
    })
}

fn edit_toml(content: &str, changes: &[Change]) -> Result<String, String> {
    let mut doc = content
        .parse::<toml_edit::DocumentMut>()
        .map_err(|e| e.to_string())?;
    for c in changes {
        // `nofoo` sets foo too
        let negated = format!("no{}", c.key);
        doc.remove(&negated);
        match &c.values {
            None => {
                doc.remove(&c.key);
            }
            Some(values) => {
                let value = if c.multi {
                    let mut array = toml_edit::Array::new();
                    for v in values {
                        array.push(toml_value(c, v)?);
                    }
                    toml_edit::Value::Array(array)
                } else {
                    match values.as_slice() {
                        [v] => toml_value(c, v)?,
                        _ => return Err(format!("{}: takes one value", c.key)),
                    }
                };
                match doc.get_mut(&c.key) {
                    Some(item) if item.is_value() => {
                        // Keep the comments around the old value
                        let decor = item.as_value().map(|v| v.decor().clone());
                        let mut value = value;
                        if let Some(d) = decor {
                            *value.decor_mut() = d;
                        }
                        *item = toml_edit::Item::Value(value);
                    }
                    _ => {
                        doc.insert(&c.key, toml_edit::Item::Value(value));
                    }
                }
            }
        }
    }
    Ok(doc.to_string())
}

/// The file's text with the changes made, and checked: read back, it must
/// set exactly what it set before with the changed options replaced
pub fn edit(path: &Path, content: Option<&str>, changes: &[Change]) -> Result<String, String> {
    let format = format_of(path, content);
    let old = match content {
        Some(text) => read_values(path, text)?,
        None => Values::new(),
    };
    let text = match format {
        Format::Divi => edit_divi(content.unwrap_or(""), changes)?,
        Format::Toml => edit_toml(content.unwrap_or(""), changes)?,
    };
    let mut expected = old;
    for c in changes {
        match &c.values {
            Some(v) if !v.is_empty() => {
                expected.insert(c.key.clone(), v.clone());
            }
            _ => {
                expected.remove(&c.key);
            }
        }
    }
    if format_of(path, Some(&text)) != format {
        return Err("the edited file would be read in another format; edit it by hand".to_string());
    }
    let got = read_values(path, &text)?;
    if got != expected {
        let differ: Vec<&String> = expected
            .keys()
            .chain(got.keys())
            .filter(|k| expected.get(*k) != got.get(*k))
            .collect();
        return Err(format!(
            "the edited file would not read back as intended ({}); edit it by hand",
            differ
                .iter()
                .map(|k| k.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    Ok(text)
}

fn backup_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".bak");
    path.with_file_name(name)
}

/// Make the changes to the file at `path` (creating it if need be). The old
/// file is kept as `<name>.bak`; the new one keeps its mode, or is the
/// owner's alone when new.
pub fn apply(path: &Path, changes: &[Change]) -> Result<(), String> {
    let content = match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(format!("cannot read {}: {}", path.display(), e)),
    };
    let text = edit(path, content.as_deref(), changes)?;
    let io = |e: std::io::Error| format!("cannot write {}: {}", path.display(), e);
    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o600)
    };
    if content.is_some() {
        std::fs::copy(path, backup_path(path)).map_err(io)?;
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    let tmp = dir.join(format!(
        ".{}.webui.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("conf")
    ));
    {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(mode);
        }
        let mut file = options.open(&tmp).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(mode))
                .map_err(io)?;
        }
        file.write_all(text.as_bytes()).map_err(io)?;
        file.sync_all().map_err(io)?;
    }
    std::fs::rename(&tmp, path).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(key: &str, values: &[&str], toml: TomlType, multi: bool) -> Change {
        Change {
            key: key.into(),
            values: Some(values.iter().map(|s| s.to_string()).collect()),
            toml,
            multi,
        }
    }

    fn unset(key: &str) -> Change {
        Change {
            key: key.into(),
            values: None,
            toml: TomlType::Str,
            multi: false,
        }
    }

    #[test]
    fn divi_edit_replaces_every_spelling_in_place() {
        let path = Path::new("/d/divi.conf");
        let before = "# my node\nrpcuser=bert\n-port=1 # old port\nnolisten=1\naddnode=a\n\
                      addnode=b\n[test]\nport=2\nmaxconnections=8\n";
        let after = edit(
            path,
            Some(before),
            &[
                set("port", &["51472"], TomlType::Int, false),
                set("listen", &["1"], TomlType::Bool, false),
                set("addnode", &["c"], TomlType::Str, true),
                unset("maxconnections"),
                set("staking", &["0"], TomlType::Bool, false),
            ],
        )
        .unwrap();
        assert_eq!(
            after,
            "# my node\nrpcuser=bert\n# old port\nport=51472\nlisten=1\naddnode=c\n\
             staking=0\n[test]\n"
        );
        let values = read_values(path, &after).unwrap();
        assert_eq!(values["rpcuser"], ["bert"]);
        assert_eq!(values["listen"], ["1"]);
        assert!(!values.contains_key("maxconnections"));
    }

    #[test]
    fn divi_edit_refuses_a_comment_mark_in_a_value() {
        let err = edit(
            Path::new("divi.conf"),
            Some(""),
            &[set("rpcuser", &["a#b"], TomlType::Str, false)],
        )
        .unwrap_err();
        assert!(err.contains('#'), "{err}");
    }

    #[test]
    fn toml_edit_keeps_comments_and_types() {
        let path = Path::new("/d/irondivi.conf");
        let before =
            "# mine\nrpcuser = \"bert\"  # who\nport = 1\nnolisten = true\n\n[extra]\nx = 1\n";
        let after = edit(
            path,
            Some(before),
            &[
                set("port", &["51472"], TomlType::Int, false),
                set("listen", &["1"], TomlType::Bool, false),
                set("addnode", &["a", "b"], TomlType::Str, true),
            ],
        )
        .unwrap();
        assert!(after.contains("# mine"), "{after}");
        assert!(after.contains("# who"), "{after}");
        assert!(after.contains("port = 51472"), "{after}");
        assert!(after.contains("listen = true"), "{after}");
        assert!(after.contains("addnode = [\"a\", \"b\"]"), "{after}");
        assert!(!after.contains("nolisten"), "{after}");
        let values = read_values(path, &after).unwrap();
        assert_eq!(values["addnode"], ["a", "b"]);
        assert!(!values.contains_key("x"), "a table is not read");
    }

    #[test]
    fn a_new_file_takes_its_names_format() {
        let toml = edit(
            Path::new("/d/irondivi.conf"),
            None,
            &[set("staking", &["1"], TomlType::Bool, false)],
        )
        .unwrap();
        assert_eq!(toml.trim(), "staking = true");
        let divi = edit(
            Path::new("/d/divi.conf"),
            None,
            &[set("staking", &["1"], TomlType::Bool, false)],
        )
        .unwrap();
        assert_eq!(divi, "staking=1\n");
    }

    #[test]
    fn apply_keeps_a_backup_and_the_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("divi.conf");
        std::fs::write(&path, "port=1\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        apply(&path, &[set("port", &["2"], TomlType::Int, false)]).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "port=2\n");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("divi.conf.bak")).unwrap(),
            "port=1\n"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o640);
        }
    }
}
