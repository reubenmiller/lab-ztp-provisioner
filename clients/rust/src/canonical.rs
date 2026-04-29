//! RFC 8785 (JSON Canonicalization Scheme) implementation.
//!
//! Rules:
//! - Object keys sorted lexicographically by UTF-8 code unit (= Rust's str::cmp).
//! - No insignificant whitespace.
//! - Strings encoded without HTML escaping (<, >, & are NOT escaped).
//! - Control chars (U+0000–U+001F) encoded as \\uXXXX (4 lowercase hex digits).
//! - Numbers emitted as serde_json::Number::to_string() (integer-preserving).
//! - Arrays in original order.
//!
//! This matches Go's Canonicalize in pkg/protocol/canonical.go.

use serde::Serialize;

/// Serialise `value` to its canonical JSON byte form.
pub fn canonicalize<T: Serialize>(value: &T) -> serde_json::Result<Vec<u8>> {
    let v = serde_json::to_value(value)?;
    Ok(canonicalize_value(&v))
}

/// Canonicalise an already-parsed JSON [`serde_json::Value`].
pub fn canonicalize_value(v: &serde_json::Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    write_canonical(&mut out, v);
    out
}

fn write_canonical(out: &mut Vec<u8>, v: &serde_json::Value) {
    use serde_json::Value::*;
    match v {
        Null => out.extend_from_slice(b"null"),
        Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        String(s) => write_json_string(out, s),
        Array(arr) => {
            out.push(b'[');
            for (i, elem) in arr.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(out, elem);
            }
            out.push(b']');
        }
        Object(map) => {
            // Collect and sort keys in UTF-8 byte order (= Go's sort.Strings).
            let mut keys: Vec<&str> = map.keys().map(|s| s.as_str()).collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_json_string(out, k);
                out.push(b':');
                write_canonical(out, map.get(*k).expect("key from keys() must exist"));
            }
            out.push(b'}');
        }
    }
}

/// Write a JSON-encoded string with surrounding quotes.
/// Escaping rules mirror Go's json.Encoder with SetEscapeHTML(false):
/// - `"` → `\"`  ,  `\` → `\\`
/// - `\n` → `\n` ,  `\r` → `\r` ,  `\t` → `\t`
/// - U+0000–U+001F (except above) → `\uXXXX` (4 lowercase hex digits)
/// - All other chars emitted as-is (UTF-8; no HTML escaping).
fn write_json_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                // e.g. \u0001
                let s = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(s.as_bytes());
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys() {
        let v = json!({"b": 1, "a": 2});
        assert_eq!(canonicalize_value(&v), b"{\"a\":2,\"b\":1}");
    }

    #[test]
    fn nested_keys_sorted() {
        let v = json!({"b": 1, "a": {"y": 2, "x": 3}});
        assert_eq!(canonicalize_value(&v), b"{\"a\":{\"x\":3,\"y\":2},\"b\":1}");
    }

    #[test]
    fn array_preserves_order() {
        let v = json!([3, 1, 2]);
        assert_eq!(canonicalize_value(&v), b"[3,1,2]");
    }

    #[test]
    fn null_bool() {
        let v = json!({"a": true, "b": false, "z": null});
        assert_eq!(canonicalize_value(&v), b"{\"a\":true,\"b\":false,\"z\":null}");
    }

    #[test]
    fn string_escaping() {
        let v = json!("line1\nline2");
        assert_eq!(canonicalize_value(&v), b"\"line1\\nline2\"");
    }

    #[test]
    fn no_html_escaping() {
        // Go's SetEscapeHTML(false): <, >, & are NOT escaped
        let v = json!({"k": "<a>&<b>"});
        assert_eq!(canonicalize_value(&v), b"{\"k\":\"<a>&<b>\"}");
    }

    #[test]
    fn unicode_key_order() {
        // "é" (0xC3 0xA9) < "中" (0xE4 0xB8 0xAD) in byte order
        let v = json!({"\u{4e2d}": 2, "\u{00e9}": 1});
        let got = canonicalize_value(&v);
        let s = std::str::from_utf8(&got).unwrap();
        assert!(s.starts_with("{\"é\""), "expected é before 中, got {s}");
    }
}
