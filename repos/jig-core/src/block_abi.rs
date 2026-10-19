//! Canonical encoding of block-ABI values, and the hashes built on it (JEP-0006).
//!
//! Two executors agree on a run when they agree on the hash of what the block returned
//! (design decision A3). That hash is computed by the host over the lifted WIT value, so the
//! value needs exactly one byte encoding. This module fixes it: each WIT value maps to one
//! [`dcbor::Value`] by the table below, and [`crate::dcbor`] encodes that under the core
//! deterministic rules of RFC 8949 §4.2.1. The same encoding identifies a run's input
//! (`invocation_hash`). This module owns only the mapping and the refusals that keep it
//! one-to-one; the byte encoding is `dcbor`'s, shared with every other signed object.
//!
//! # Type mapping
//!
//! | WIT type | CBOR |
//! | --- | --- |
//! | `bool` | `true` / `false` |
//! | `u8`…`u64`, `s8`…`s64` | integer (major type 0 or 1), shortest form |
//! | `char` | text string holding that one character |
//! | `string` | text string |
//! | `list<u8>` | byte string |
//! | any other `list<T>`, `tuple<…>` | array |
//! | `record` | map from field name (text) to value, keys in canonical order |
//! | `variant` case, `result` | array `[case]` or `[case, payload]`; `result` uses the cases `ok` and `err` |
//! | `enum` case | text string |
//! | `option<T>` | `none` is `null`; `some(x)` is the one-element array `[x]` |
//!
//! `f32` and `f64` have no mapping: the determinism profile `jig-det-1` keeps floats out of the
//! ABI (A2), and a value that needs one cannot be encoded. `flags`, resources, futures and
//! streams are not used by `jig:block` and are not representable either.
//!
//! `option` wraps `some` in an array so that `option<option<T>>` stays unambiguous: `none` is
//! `null`, `some(none)` is `[null]`.

use std::collections::BTreeSet;

use crate::dcbor::{self, Value};

/// A lifted WIT value of a type the block ABI allows.
///
/// The caller maps each value by its WIT type, so a `list<u8>` is always [`WitValue::Bytes`] and
/// never a [`WitValue::List`] of [`WitValue::U8`]. The encoder refuses the second form rather
/// than give one WIT value two encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitValue {
    Bool(bool),
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    S8(i8),
    S16(i16),
    S32(i32),
    S64(i64),
    Char(char),
    String(String),
    /// A `list<u8>`.
    Bytes(Vec<u8>),
    /// A `list<T>` for any `T` other than `u8`.
    List(Vec<WitValue>),
    /// Field names and values. Field order does not affect the encoding.
    Record(Vec<(String, WitValue)>),
    Tuple(Vec<WitValue>),
    Variant {
        case: String,
        payload: Option<Box<WitValue>>,
    },
    Enum(String),
    Option(Option<Box<WitValue>>),
    Result(Result<Option<Box<WitValue>>, Option<Box<WitValue>>>),
}

/// Why a value has no canonical encoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EncodeError {
    #[error("a list<u8> must be WitValue::Bytes, not a List of U8")]
    ByteListAsList,
    #[error("record has two fields named `{0}`")]
    DuplicateField(String),
}

/// Map `value` to the one [`dcbor::Value`] the table above gives it.
pub fn to_cbor(value: &WitValue) -> Result<Value, EncodeError> {
    Ok(match value {
        WitValue::Bool(b) => Value::Bool(*b),
        WitValue::U8(n) => Value::Unsigned(u64::from(*n)),
        WitValue::U16(n) => Value::Unsigned(u64::from(*n)),
        WitValue::U32(n) => Value::Unsigned(u64::from(*n)),
        WitValue::U64(n) => Value::Unsigned(*n),
        WitValue::S8(n) => Value::int(i64::from(*n)),
        WitValue::S16(n) => Value::int(i64::from(*n)),
        WitValue::S32(n) => Value::int(i64::from(*n)),
        WitValue::S64(n) => Value::int(*n),
        WitValue::Char(c) => Value::Text(c.to_string()),
        WitValue::String(s) => Value::Text(s.clone()),
        WitValue::Bytes(b) => Value::Bytes(b.clone()),
        WitValue::List(items) => {
            if items.iter().any(|v| matches!(v, WitValue::U8(_))) {
                return Err(EncodeError::ByteListAsList);
            }
            Value::Array(items.iter().map(to_cbor).collect::<Result<_, _>>()?)
        }
        WitValue::Tuple(items) => {
            Value::Array(items.iter().map(to_cbor).collect::<Result<_, _>>()?)
        }
        WitValue::Record(fields) => {
            let mut seen = BTreeSet::new();
            let mut entries = Vec::with_capacity(fields.len());
            for (name, v) in fields {
                if !seen.insert(name.as_str()) {
                    return Err(EncodeError::DuplicateField(name.clone()));
                }
                entries.push((Value::Text(name.clone()), to_cbor(v)?));
            }
            Value::Map(entries)
        }
        WitValue::Variant { case, payload } => tagged(case, payload.as_deref())?,
        WitValue::Enum(case) => Value::Text(case.clone()),
        WitValue::Option(None) => Value::Null,
        WitValue::Option(Some(v)) => Value::Array(vec![to_cbor(v)?]),
        WitValue::Result(Ok(p)) => tagged("ok", p.as_deref())?,
        WitValue::Result(Err(p)) => tagged("err", p.as_deref())?,
    })
}

fn tagged(case: &str, payload: Option<&WitValue>) -> Result<Value, EncodeError> {
    let mut items = vec![Value::Text(case.to_string())];
    if let Some(p) = payload {
        items.push(to_cbor(p)?);
    }
    Ok(Value::Array(items))
}

/// Encode `value` as deterministic CBOR: [`to_cbor`], then [`dcbor::encode`].
pub fn encode(value: &WitValue) -> Result<Vec<u8>, EncodeError> {
    // `to_cbor` has already refused repeated record fields, which is the only way `dcbor` can
    // fail, so a `dcbor` error here would be a bug in this mapping.
    dcbor::encode(&to_cbor(value)?).map_err(|e| unreachable!("dcbor refused a mapped value: {e:?}"))
}

/// The hash two executors compare for a comparable outcome (A3): BLAKE3, keyed by a context
/// string so it can never collide with another use of the same bytes, over [`encode`]. Pass
/// the export's whole return value, `ok` or `err`.
pub fn outcome_hash(returned: &WitValue) -> Result<String, EncodeError> {
    hash_with_context("jig:block outcome v1", returned)
}

/// The hash that identifies a run's input: the `invocation` record, encoded canonically.
pub fn invocation_hash(invocation: &WitValue) -> Result<String, EncodeError> {
    hash_with_context("jig:block invocation v1", invocation)
}

fn hash_with_context(context: &str, value: &WitValue) -> Result<String, EncodeError> {
    let bytes = encode(value)?;
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&bytes);
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &WitValue) -> String {
        hex::encode(encode(v).unwrap())
    }

    fn s(x: &str) -> WitValue {
        WitValue::String(x.to_string())
    }

    #[test]
    fn integers_use_the_shortest_form() {
        // RFC 8949 Appendix A examples.
        assert_eq!(hex(&WitValue::U64(0)), "00");
        assert_eq!(hex(&WitValue::U64(23)), "17");
        assert_eq!(hex(&WitValue::U64(24)), "1818");
        assert_eq!(hex(&WitValue::U64(1000)), "1903e8");
        assert_eq!(hex(&WitValue::U64(1_000_000)), "1a000f4240");
        assert_eq!(hex(&WitValue::U64(u64::MAX)), "1bffffffffffffffff");
        assert_eq!(hex(&WitValue::S64(-1)), "20");
        assert_eq!(hex(&WitValue::S64(-1000)), "3903e7");
        assert_eq!(hex(&WitValue::S64(i64::MIN)), "3b7fffffffffffffff");
    }

    #[test]
    fn integer_width_does_not_change_the_encoding() {
        assert_eq!(encode(&WitValue::U8(7)), encode(&WitValue::U64(7)));
        assert_eq!(encode(&WitValue::S8(-7)), encode(&WitValue::S64(-7)));
    }

    #[test]
    fn strings_bytes_and_chars() {
        assert_eq!(hex(&s("")), "60");
        assert_eq!(hex(&s("IETF")), "6449455446");
        assert_eq!(hex(&WitValue::Char('ü')), "62c3bc");
        assert_eq!(hex(&WitValue::Bytes(vec![1, 2, 3, 4])), "4401020304");
    }

    #[test]
    fn record_fields_are_ordered_by_encoded_key_whatever_their_input_order() {
        let a = WitValue::Record(vec![
            ("media-type".into(), s("text/plain")),
            ("body".into(), WitValue::Bytes(b"hi".to_vec())),
        ]);
        let b = WitValue::Record(vec![
            ("body".into(), WitValue::Bytes(b"hi".to_vec())),
            ("media-type".into(), s("text/plain")),
        ]);
        assert_eq!(encode(&a), encode(&b));
        // "body" (encoded 0x64...) sorts before "media-type" (0x6a...): shorter keys first.
        assert_eq!(
            hex(&a),
            "a2\
             64626f6479426869\
             6a6d656469612d74797065\
             6a746578742f706c61696e"
        );
    }

    #[test]
    fn option_nesting_is_unambiguous() {
        let none = WitValue::Option(None);
        let some_none = WitValue::Option(Some(Box::new(WitValue::Option(None))));
        assert_eq!(hex(&none), "f6");
        assert_eq!(hex(&some_none), "81f6");
    }

    #[test]
    fn results_and_variants_are_tagged_arrays() {
        let ok_unit = WitValue::Result(Ok(None));
        let err = WitValue::Result(Err(Some(Box::new(WitValue::Variant {
            case: "failed".into(),
            payload: Some(Box::new(s("x"))),
        }))));
        assert_eq!(hex(&ok_unit), "81626f6b");
        // ["err", ["failed", "x"]]
        assert_eq!(hex(&err), "826365727282666661696c65646178");
    }

    #[test]
    fn every_encoding_is_accepted_by_the_strict_decoder() {
        let v = WitValue::Record(vec![
            (
                "z".into(),
                WitValue::Option(Some(Box::new(WitValue::S64(-5)))),
            ),
            ("aa".into(), WitValue::List(vec![s("x"), s("y")])),
            ("b".into(), WitValue::Result(Err(None))),
        ]);
        let bytes = encode(&v).unwrap();
        let decoded = dcbor::decode(&bytes).expect("dcbor accepts what this module emits");
        assert_eq!(dcbor::encode(&decoded).unwrap(), bytes);
    }

    #[test]
    fn a_byte_list_spelled_as_a_list_is_refused() {
        let wrong = WitValue::List(vec![WitValue::U8(1)]);
        assert_eq!(encode(&wrong), Err(EncodeError::ByteListAsList));
    }

    #[test]
    fn duplicate_record_fields_are_refused() {
        let dup = WitValue::Record(vec![("a".into(), s("1")), ("a".into(), s("2"))]);
        assert_eq!(encode(&dup), Err(EncodeError::DuplicateField("a".into())));
    }

    #[test]
    fn outcome_and_invocation_hashes_are_domain_separated() {
        let v = s("same bytes");
        let o = outcome_hash(&v).unwrap();
        let i = invocation_hash(&v).unwrap();
        assert!(o.starts_with("blake3:") && i.starts_with("blake3:"));
        assert_ne!(o, i);
        assert_ne!(
            o,
            format!("blake3:{}", blake3::hash(&encode(&v).unwrap()).to_hex())
        );
    }
}
