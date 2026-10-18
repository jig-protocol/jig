//! Deterministic CBOR (RFC 8949 section 4.2.1, "core deterministic encoding").
//!
//! The one CBOR encoder jig signs and hashes with: COSE envelopes ([`crate::cose`]),
//! naming objects, `ingest` records, identity links, block-ABI values and receipts
//! all go through it, so a value has exactly one byte encoding whoever produced it.
//! The rules, as RFC 8949 section 4.2.1 states them:
//!
//! - every head (integer, length, tag number) uses its shortest form;
//! - every length is definite;
//! - map keys are sorted by the bytewise order of their own deterministic
//!   encodings, so `"b"` (`0x61 0x62`) comes before `"aa"` (`0x62 0x61 0x61`),
//!   and no key repeats.
//!
//! [`Value`] has no floating-point variant and no simple values beyond `false`,
//! `true` and `null`. [`decode`] is strict: it refuses any input that is not
//! already in deterministic form (a non-shortest head, an indefinite length,
//! keys out of order or repeated, a float, invalid UTF-8, trailing bytes), so a
//! receiver never accepts two encodings of one value. It bounds nesting depth,
//! and checks every claimed length against the bytes left before allocating.
//!
//! No dependencies, and no feature gate, so the block ABI can use it without
//! the signing stack.

/// A CBOR data item of the kinds jig uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// Major type 0: the unsigned integer `n`.
    Unsigned(u64),
    /// Major type 1: the negative integer `-1 - n`.
    Negative(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Entries in any order; [`encode`] sorts them.
    Map(Vec<(Value, Value)>),
    Tag(u64, Box<Value>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum DcborError {
    #[error("not well-formed CBOR")]
    Malformed,
    #[error("CBOR is not in deterministic form")]
    NotDeterministic,
    #[error("floating-point and unassigned simple values are not allowed")]
    Unsupported,
    #[error("a map key repeats")]
    DuplicateKey,
    #[error("CBOR nests deeper than {MAX_DEPTH} levels")]
    TooDeep,
}

/// Deepest nesting [`decode`] accepts. jig's objects nest a handful of levels.
pub const MAX_DEPTH: usize = 32;

const UNSIGNED: u8 = 0;
const NEGATIVE: u8 = 1;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const ARRAY: u8 = 4;
const MAP: u8 = 5;
const TAG: u8 = 6;
const SIMPLE: u8 = 7;
const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;

impl Value {
    pub fn int(n: i64) -> Self {
        if n >= 0 {
            Value::Unsigned(n as u64)
        } else {
            // CBOR stores a negative n as -1 - n, which is never negative.
            Value::Negative(!(n as u64))
        }
    }

    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }

    /// A map with text keys, the shape of every jig payload.
    pub fn text_map<'a>(entries: impl IntoIterator<Item = (&'a str, Value)>) -> Self {
        Value::Map(
            entries
                .into_iter()
                .map(|(k, v)| (Value::text(k), v))
                .collect(),
        )
    }

    pub fn as_i64(&self) -> Option<i64> {
        match *self {
            Value::Unsigned(n) => i64::try_from(n).ok(),
            Value::Negative(n) => i64::try_from(n).ok().map(|n| -1 - n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match *self {
            Value::Unsigned(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(t) => Some(t),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// The value under text key `key`, if this is a map.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(entries) => entries
                .iter()
                .find(|(k, _)| k.as_text() == Some(key))
                .map(|(_, v)| v),
            _ => None,
        }
    }
}

/// Encode `value` deterministically. Maps are sorted at every depth; the only
/// failure is a repeated map key.
pub fn encode(value: &Value) -> Result<Vec<u8>, DcborError> {
    let mut out = Vec::new();
    encode_into(value, &mut out)?;
    Ok(out)
}

/// The head of a data item, with its argument in the shortest form.
fn head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    match arg {
        0..=23 => out.push(m | arg as u8),
        24..=0xff => out.extend_from_slice(&[m | 24, arg as u8]),
        0x100..=0xffff => {
            out.push(m | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(m | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push(m | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), DcborError> {
    match value {
        Value::Unsigned(n) => head(UNSIGNED, *n, out),
        Value::Negative(n) => head(NEGATIVE, *n, out),
        Value::Bytes(b) => {
            head(BYTES, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(t) => {
            head(TEXT, t.len() as u64, out);
            out.extend_from_slice(t.as_bytes());
        }
        Value::Array(items) => {
            head(ARRAY, items.len() as u64, out);
            for v in items {
                encode_into(v, out)?;
            }
        }
        Value::Map(entries) => {
            let mut encoded = Vec::with_capacity(entries.len());
            for (k, v) in entries {
                encoded.push((encode(k)?, encode(v)?));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|w| w[0].0 == w[1].0) {
                return Err(DcborError::DuplicateKey);
            }
            head(MAP, encoded.len() as u64, out);
            for (k, v) in encoded {
                out.extend_from_slice(&k);
                out.extend_from_slice(&v);
            }
        }
        Value::Tag(n, v) => {
            head(TAG, *n, out);
            encode_into(v, out)?;
        }
        Value::Bool(b) => out.push(if *b { TRUE } else { FALSE }),
        Value::Null => out.push(NULL),
    }
    Ok(())
}

/// Decode `bytes`, which must be exactly one data item in deterministic form.
pub fn decode(bytes: &[u8]) -> Result<Value, DcborError> {
    let mut r = Reader { bytes, pos: 0 };
    let value = r.item(0)?;
    if r.pos != bytes.len() {
        return Err(DcborError::Malformed);
    }
    Ok(value)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], DcborError> {
        let end = self.pos.checked_add(n).ok_or(DcborError::Malformed)?;
        let s = self.bytes.get(self.pos..end).ok_or(DcborError::Malformed)?;
        self.pos = end;
        Ok(s)
    }

    /// Read a head; refuse indefinite lengths and any non-shortest argument.
    fn head(&mut self) -> Result<(u8, u8, u64), DcborError> {
        let initial = self.take(1)?[0];
        let (major, info) = (initial >> 5, initial & 0x1f);
        let arg = match info {
            0..=23 => u64::from(info),
            24..=27 => {
                let width = 1usize << (info - 24);
                let arg = self
                    .take(width)?
                    .iter()
                    .fold(0u64, |acc, b| (acc << 8) | u64::from(*b));
                let shortest = match width {
                    1 => arg >= 24,
                    2 => arg > 0xff,
                    4 => arg > 0xffff,
                    _ => arg > 0xffff_ffff,
                };
                // A float's width is not a length, but floats are refused anyway.
                if !shortest && major != SIMPLE {
                    return Err(DcborError::NotDeterministic);
                }
                arg
            }
            31 if major != SIMPLE && major >= BYTES && major != TAG => {
                return Err(DcborError::NotDeterministic);
            }
            _ => return Err(DcborError::Malformed),
        };
        Ok((major, info, arg))
    }

    /// A length that cannot exceed the bytes left, so a hostile length never
    /// drives an allocation.
    fn len(&self, arg: u64) -> Result<usize, DcborError> {
        usize::try_from(arg)
            .ok()
            .filter(|n| *n <= self.bytes.len() - self.pos)
            .ok_or(DcborError::Malformed)
    }

    fn item(&mut self, depth: usize) -> Result<Value, DcborError> {
        if depth > MAX_DEPTH {
            return Err(DcborError::TooDeep);
        }
        let (major, info, arg) = self.head()?;
        Ok(match major {
            UNSIGNED => Value::Unsigned(arg),
            NEGATIVE => Value::Negative(arg),
            BYTES => {
                let n = self.len(arg)?;
                Value::Bytes(self.take(n)?.to_vec())
            }
            TEXT => {
                let n = self.len(arg)?;
                let s = std::str::from_utf8(self.take(n)?).map_err(|_| DcborError::Malformed)?;
                Value::Text(s.to_string())
            }
            ARRAY => {
                // Every item takes at least one byte.
                let n = self.len(arg)?;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.item(depth + 1)?);
                }
                Value::Array(items)
            }
            MAP => {
                let n = self.len(arg)?;
                let mut entries = Vec::with_capacity(n);
                let mut prev: Option<&[u8]> = None;
                let bytes = self.bytes;
                for _ in 0..n {
                    let start = self.pos;
                    let k = self.item(depth + 1)?;
                    let key_bytes = &bytes[start..self.pos];
                    match prev {
                        Some(p) if p == key_bytes => return Err(DcborError::DuplicateKey),
                        Some(p) if p > key_bytes => return Err(DcborError::NotDeterministic),
                        _ => {}
                    }
                    prev = Some(key_bytes);
                    entries.push((k, self.item(depth + 1)?));
                }
                Value::Map(entries)
            }
            TAG => Value::Tag(arg, Box::new(self.item(depth + 1)?)),
            _ => match (info, arg) {
                (20, _) => Value::Bool(false),
                (21, _) => Value::Bool(true),
                (22, _) => Value::Null,
                _ => return Err(DcborError::Unsupported),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(v: &Value) -> String {
        hex::encode(encode(v).unwrap())
    }

    fn round_trip(h: &str) -> Value {
        let bytes = hex::decode(h).unwrap();
        let v = decode(&bytes).unwrap();
        assert_eq!(encode(&v).unwrap(), bytes, "{h} re-encodes to itself");
        v
    }

    /// RFC 8949 Appendix A, and the vectors of the block ABI (#148), which
    /// were cross-checked against python cbor2's canonical mode.
    #[test]
    fn conformance_vectors() {
        assert_eq!(hex(&Value::int(0)), "00");
        assert_eq!(hex(&Value::int(23)), "17");
        assert_eq!(hex(&Value::int(24)), "1818");
        assert_eq!(hex(&Value::int(1000)), "1903e8");
        assert_eq!(hex(&Value::int(1_000_000)), "1a000f4240");
        assert_eq!(hex(&Value::Unsigned(u64::MAX)), "1bffffffffffffffff");
        assert_eq!(hex(&Value::int(-1)), "20");
        assert_eq!(hex(&Value::int(-1000)), "3903e7");
        assert_eq!(hex(&Value::int(i64::MIN)), "3b7fffffffffffffff");
        assert_eq!(hex(&Value::text("")), "60");
        assert_eq!(hex(&Value::text("IETF")), "6449455446");
        assert_eq!(hex(&Value::text("ü")), "62c3bc");
        assert_eq!(hex(&Value::Bytes(vec![1, 2, 3, 4])), "4401020304");
        assert_eq!(hex(&Value::Null), "f6");
        assert_eq!(hex(&Value::Array(vec![Value::Null])), "81f6");
        // ["err", ["failed", "x"]]
        let err = Value::Array(vec![
            Value::text("err"),
            Value::Array(vec![Value::text("failed"), Value::text("x")]),
        ]);
        assert_eq!(hex(&err), "826365727282666661696c65646178");
        // {"media-type": "text/plain", "body": h'6869'}: shorter key first.
        let record = Value::text_map([
            ("media-type", Value::text("text/plain")),
            ("body", Value::Bytes(b"hi".to_vec())),
        ]);
        assert_eq!(
            hex(&record),
            "a264626f64794268696a6d656469612d747970656a746578742f706c61696e"
        );
        // 1(1363896240): a tag.
        assert_eq!(
            hex(&Value::Tag(1, Box::new(Value::int(1_363_896_240)))),
            "c11a514b67b0"
        );
        for h in [
            "00",
            "1bffffffffffffffff",
            "3b7fffffffffffffff",
            "f4",
            "f5",
            "f6",
            "83010203",
            "a201020304",
            "c11a514b67b0",
            "a264626f64794268696a6d656469612d747970656a746578742f706c61696e",
        ] {
            round_trip(h);
        }
        assert_eq!(round_trip("3903e7").as_i64(), Some(-1000));
    }

    #[test]
    fn map_keys_sort_by_encoded_bytes_not_lexically() {
        // Lexically "aa" < "b"; by encoded bytes "b" (0x61 0x62) < "aa" (0x62 ...).
        let v = Value::text_map([("aa", Value::int(1)), ("b", Value::int(2))]);
        assert_eq!(
            encode(&v).unwrap(),
            [0xa2, 0x61, b'b', 0x02, 0x62, b'a', b'a', 0x01]
        );
        // Keys of mixed types sort by their encodings too: 10 (0x0a) < -1 (0x20) < "a".
        let mixed = Value::Map(vec![
            (Value::text("a"), Value::Null),
            (Value::int(-1), Value::Null),
            (Value::int(10), Value::Null),
        ]);
        assert_eq!(hex(&mixed), "a30af620f66161f6");
    }

    #[test]
    fn non_deterministic_input_is_refused() {
        for (h, want) in [
            // Map keys out of order, and repeated.
            ("a2626161016162 02", DcborError::NotDeterministic),
            ("a2616101616102", DcborError::DuplicateKey),
            // Non-shortest heads: an integer, a length, a tag number.
            ("1801", DcborError::NotDeterministic),
            ("190017", DcborError::NotDeterministic),
            ("5801 00", DcborError::NotDeterministic),
            ("d80101", DcborError::NotDeterministic),
            // Indefinite-length strings, arrays and maps.
            ("5f4100ff", DcborError::NotDeterministic),
            ("9f01ff", DcborError::NotDeterministic),
            ("bf6161 01ff", DcborError::NotDeterministic),
            // Floats, undefined and other simple values.
            ("f93c00", DcborError::Unsupported),
            ("fb3ff0000000000000", DcborError::Unsupported),
            ("f7", DcborError::Unsupported),
            ("f0", DcborError::Unsupported),
            // Reserved additional information, truncation, trailing bytes, bad UTF-8.
            ("1c", DcborError::Malformed),
            ("1a0001", DcborError::Malformed),
            ("0000", DcborError::Malformed),
            ("62c328", DcborError::Malformed),
        ] {
            let bytes = hex::decode(h.replace(' ', "")).unwrap();
            assert_eq!(decode(&bytes), Err(want), "{h}");
        }
    }

    #[test]
    fn hostile_lengths_and_depths_are_refused_without_allocating() {
        // A byte string, an array and a map each claiming 2^64-1 entries.
        for h in [
            "5bffffffffffffffff",
            "9bffffffffffffffff",
            "bbffffffffffffffff",
        ] {
            assert_eq!(decode(&hex::decode(h).unwrap()), Err(DcborError::Malformed));
        }
        let mut deep = vec![0x81; MAX_DEPTH + 1];
        deep.push(0x00);
        assert_eq!(decode(&deep), Err(DcborError::TooDeep));
        let mut ok = vec![0x81; MAX_DEPTH];
        ok.push(0x00);
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn repeated_keys_are_refused_on_encode() {
        let v = Value::text_map([("a", Value::int(1)), ("a", Value::int(2))]);
        assert_eq!(encode(&v), Err(DcborError::DuplicateKey));
    }
}
