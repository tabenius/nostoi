//! Core canonical JSON: the bytes Python's
//! `json.dumps(value, sort_keys=True, separators=(",", ":"))` produces.
//!
//! This is the encoding WeftMark's ledger hashes, and the one `nostoi-v1`
//! hashes, so any Python program can compute a Nostoi digest with the standard
//! library alone. The rules:
//!
//! - object keys sorted by code point, no whitespace, `,` and `:` separators;
//! - strings escaped as Python's default `ensure_ascii=True` does: `\"`, `\\`,
//!   `\b`, `\f`, `\n`, `\r`, `\t`, and `\uXXXX` (lowercase hex, UTF-16 surrogate
//!   pairs above U+FFFF) for everything else outside printable ASCII, DEL
//!   included; `/` is not escaped;
//! - numbers exactly as written: records are parsed with serde_json's
//!   `arbitrary_precision`, so a producer's integers (any size) and floats
//!   (Python `repr`, e.g. `1e+16`, `-0.0`) re-encode to the same bytes.
//!
//! Numbers written *by Nostoi* are integers only (see [`check_native`]): a float
//! has more than one spelling, and a digest must not depend on which one a
//! language picks.

use serde_json::Value;
use std::fmt::Write as _;

/// Encode `value` canonically.
pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(out, text),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            // Rust orders strings by UTF-8 bytes, which is code point order:
            // the order Python's sort_keys uses.
            keys.sort();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[key.as_str()]);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ' '..='~' => out.push(ch),
            _ => {
                let mut units = [0u16; 2];
                for unit in ch.encode_utf16(&mut units) {
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

/// Refuse what a `nostoi-v1` record must not contain: floats (their spelling
/// differs between languages), and integers outside the 64-bit range most
/// JSON parsers keep exactly.
pub fn check_native(value: &Value) -> Result<(), String> {
    match value {
        Value::Number(number) => {
            if number.is_i64() || number.is_u64() {
                Ok(())
            } else {
                Err(format!(
                    "{number} is not a 64-bit integer; write decimals and large numbers as strings"
                ))
            }
        }
        Value::Array(items) => items.iter().try_for_each(check_native),
        Value::Object(map) => map.values().try_for_each(check_native),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn matches_python_ensure_ascii_escaping() {
        let value = parse(r#"{"b":"går 🦆 —","a":"t\tn\nq\"s\\/\u0007\u007f~"}"#);
        assert_eq!(
            to_string(&value),
            r#"{"a":"t\tn\nq\"s\\/\u0007\u007f~","b":"g\u00e5r \ud83e\udd86 \u2014"}"#
        );
    }

    #[test]
    fn numbers_keep_their_written_form() {
        let value = parse(r#"{"x":[1e+16,1e-05,-0.0,1.5,12345678901234567890,3]}"#);
        assert_eq!(
            to_string(&value),
            r#"{"x":[1e+16,1e-05,-0.0,1.5,12345678901234567890,3]}"#
        );
    }

    #[test]
    fn nested_keys_are_sorted_everywhere() {
        let value = parse(r#"{"z":[{"b":null,"a":true}],"a":{"y":false,"x":{}}}"#);
        assert_eq!(
            to_string(&value),
            r#"{"a":{"x":{},"y":false},"z":[{"a":true,"b":null}]}"#
        );
    }

    #[test]
    fn native_records_take_integers_only() {
        assert!(check_native(&parse(r#"{"n":[1,-2,18446744073709551615]}"#)).is_ok());
        assert!(check_native(&parse(r#"{"n":1.5}"#)).is_err());
        assert!(check_native(&parse(r#"{"n":[{"m":12345678901234567890123}]}"#)).is_err());
    }
}
