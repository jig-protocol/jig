//! Deterministic CBOR (RFC 8949 section 4.2.1, "core deterministic encoding").
//!
//! Every signed object jig defines is COSE over deterministic CBOR, so the bytes
//! that are signed and hashed depend only on the value, never on the encoder.
//! The rules, as RFC 8949 section 4.2.1 states them:
//!
//! - integers and lengths use their shortest form;
//! - every length is definite;
//! - map keys are sorted by the bytewise order of their own deterministic
//!   encodings, and no key repeats.
//!
//! jig's objects use no floating-point values and no tags, so [`decode`]
//! refuses both. [`decode`] refuses any input that is not already in
//! deterministic form: it re-encodes what it parsed and requires the same
//! bytes back.

use ciborium::value::Value;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DcborError {
    #[error("not well-formed CBOR")]
    Malformed,
    #[error("CBOR is not in deterministic form")]
    NotDeterministic,
    #[error("floating-point values and tags are not allowed")]
    Unsupported,
    #[error("a map key repeats")]
    DuplicateKey,
}

/// Encode `value` deterministically. Maps are sorted at every depth.
pub fn encode(value: &Value) -> Result<Vec<u8>, DcborError> {
    let canonical = canonicalise(value)?;
    let mut out = Vec::new();
    ciborium::into_writer(&canonical, &mut out).map_err(|_| DcborError::Malformed)?;
    Ok(out)
}

/// Decode `bytes`, refusing anything not in deterministic form.
pub fn decode(bytes: &[u8]) -> Result<Value, DcborError> {
    let value: Value = ciborium::from_reader(bytes).map_err(|_| DcborError::Malformed)?;
    if encode(&value)? != bytes {
        return Err(DcborError::NotDeterministic);
    }
    Ok(value)
}

fn canonicalise(value: &Value) -> Result<Value, DcborError> {
    Ok(match value {
        Value::Integer(_) | Value::Bytes(_) | Value::Text(_) | Value::Bool(_) | Value::Null => {
            value.clone()
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(canonicalise).collect::<Result<_, _>>()?)
        }
        Value::Map(entries) => {
            let mut keyed = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                let k = canonicalise(k)?;
                let mut key_bytes = Vec::new();
                ciborium::into_writer(&k, &mut key_bytes).map_err(|_| DcborError::Malformed)?;
                keyed.push((key_bytes, k, canonicalise(v)?));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            if keyed.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(DcborError::DuplicateKey);
            }
            Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        _ => return Err(DcborError::Unsupported),
    })
}

/// A text-keyed map, the shape every jig payload uses.
pub fn text_map(entries: Vec<(&str, Value)>) -> Value {
    Value::Map(
        entries
            .into_iter()
            .map(|(k, v)| (Value::Text(k.to_string()), v))
            .collect(),
    )
}

/// Look up a text key in a decoded map.
pub fn get<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    match map {
        Value::Map(entries) => entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(t) if t == key))
            .map(|(_, v)| v),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_are_sorted_by_encoded_key() {
        // "b" (0x61 0x62) sorts before "aa" (0x62 0x61 0x61): length first.
        let v = text_map(vec![
            ("aa", Value::Integer(1.into())),
            ("b", Value::Integer(2.into())),
        ]);
        let bytes = encode(&v).unwrap();
        assert_eq!(bytes, vec![0xa2, 0x61, b'b', 0x02, 0x62, b'a', b'a', 0x01]);
        assert_eq!(
            decode(&bytes).unwrap(),
            decode(&encode(&v).unwrap()).unwrap()
        );
    }

    #[test]
    fn non_deterministic_input_is_refused() {
        // The same map with its keys out of order.
        let unsorted = vec![0xa2, 0x62, b'a', b'a', 0x01, 0x61, b'b', 0x02];
        assert_eq!(decode(&unsorted), Err(DcborError::NotDeterministic));
        // 1 encoded in two bytes instead of one.
        assert_eq!(decode(&[0x18, 0x01]), Err(DcborError::NotDeterministic));
        // An indefinite-length byte string.
        assert_eq!(
            decode(&[0x5f, 0x41, 0x00, 0xff]),
            Err(DcborError::NotDeterministic)
        );
        // A float.
        assert_eq!(decode(&[0xf9, 0x3c, 0x00]), Err(DcborError::Unsupported));
    }

    #[test]
    fn repeated_keys_are_refused() {
        let v = text_map(vec![
            ("a", Value::Integer(1.into())),
            ("a", Value::Integer(2.into())),
        ]);
        assert_eq!(encode(&v), Err(DcborError::DuplicateKey));
    }
}
