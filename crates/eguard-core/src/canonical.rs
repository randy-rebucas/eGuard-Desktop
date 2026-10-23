//! The bytes eGuard signs: JSON with object keys sorted at every level and no whitespace, exactly as
//! `canonicalJson` in `~/eguard/src/lib/browser-policy.ts` makes them (`JSON.stringify` of the sorted value).
//!
//! Byte-for-byte matters, so this follows JavaScript rather than `serde_json`'s own printer:
//! - keys sort by UTF-16 code units (`Array.prototype.sort`), not UTF-8 bytes;
//! - strings escape only `"`, `\`, and control characters (`\b \f \n \r \t`, others as lower-case `\u00xx`);
//! - numbers print as `Number.prototype.toString` does (`12.0` is `12`, `1e21` is `1e+21`, `-0` is `0`).

use serde_json::{Number, Value};
use std::fmt::Write as _;

/// The canonical JSON text of `value`.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
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
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, &map[key]);
            }
            out.push('}');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_number(out: &mut String, n: &Number) {
    if let Some(i) = n.as_i64() {
        let _ = write!(out, "{i}");
    } else if let Some(u) = n.as_u64() {
        let _ = write!(out, "{u}");
    } else if let Some(f) = n.as_f64() {
        out.push_str(&js_number(f));
    }
}

/// `Number.prototype.toString()` for a finite double (ECMAScript `Number::toString`, radix 10).
pub fn js_number(f: f64) -> String {
    if f == 0.0 {
        return "0".to_owned();
    }
    if !f.is_finite() {
        // JSON.stringify writes these as null; JSON text can't carry them anyway
        return "null".to_owned();
    }
    let sign = if f < 0.0 { "-" } else { "" };
    // Rust's `{:e}` gives the shortest digits that round-trip, the same digits JavaScript picks
    let sci = format!("{:e}", f.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap_or((&sci, "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let k = digits.len() as i32;
    // n: the position of the decimal point relative to the digits (value = 0.digits × 10^n)
    let n = exp.parse::<i32>().unwrap_or(0) + 1;
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat((-n) as usize))
    } else {
        let e = n - 1;
        let e = if e >= 0 { format!("+{e}") } else { e.to_string() };
        if k == 1 { format!("{digits}e{e}") } else { format!("{}.{}e{e}", &digits[..1], &digits[1..]) }
    };
    format!("{sign}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    struct Vector {
        input: String,
        output: String,
    }

    /// Made by Node from the server's algorithm (tools/canonical-vectors.mjs), never by hand.
    #[test]
    fn matches_javascript_byte_for_byte() {
        let vectors: Vec<Vector> = serde_json::from_str(include_str!("../../../fixtures/canonical-vectors.json")).unwrap();
        assert!(vectors.len() >= 5);
        for v in vectors {
            let parsed: Value = serde_json::from_str(&v.input).unwrap();
            assert_eq!(canonical_json(&parsed), v.output, "input {}", v.input);
        }
    }

    #[test]
    fn shared_vector_with_server_and_extension() {
        let v: Value = serde_json::from_str(r#"{"b":[3,{"z":1,"a":"x"}],"a":null,"c":{"y":true,"x":"é"}}"#).unwrap();
        assert_eq!(canonical_json(&v), r#"{"a":null,"b":[3,{"a":"x","z":1}],"c":{"x":"é","y":true}}"#);
    }

    #[test]
    fn js_number_formats() {
        for (f, s) in [
            (1.5, "1.5"),
            (100.0, "100"),
            (1e21, "1e+21"),
            (1e20, "100000000000000000000"),
            (1e-7, "1e-7"),
            (1e-6, "0.000001"),
            (-325.0, "-325"),
            (123.456, "123.456"),
            (0.1 + 0.2, "0.30000000000000004"),
        ] {
            assert_eq!(js_number(f), s);
        }
    }
}
