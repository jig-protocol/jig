use cid::Cid;
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::error::JigError;

pub fn serialize_cid<S>(cid: &Cid, serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&cid.to_string())
}

pub fn deserialize_cid<'de, D>(deserializer: D) -> std::result::Result<Cid, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    s.parse().map_err(D::Error::custom)
}

pub fn serialize_opt_cid<S>(
    cid: &Option<Cid>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match cid {
        Some(cid) => serializer.serialize_some(&cid.to_string()),
        None => serializer.serialize_none(),
    }
}

pub fn deserialize_opt_cid<'de, D>(deserializer: D) -> std::result::Result<Option<Cid>, D::Error>
where
    D: Deserializer<'de>,
{
    let option = Option::<String>::deserialize(deserializer)?;
    option.map_or(Ok(None), |s| s.parse().map(Some).map_err(D::Error::custom))
}

pub fn serialize_cid_vec<S>(cids: &[Cid], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let strings: Vec<String> = cids.iter().map(|cid| cid.to_string()).collect();
    strings.serialize(serializer)
}

pub fn deserialize_cid_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<Cid>, D::Error>
where
    D: Deserializer<'de>,
{
    let strings = Vec::<String>::deserialize(deserializer)?;
    strings
        .into_iter()
        .map(|s| s.parse().map_err(D::Error::custom))
        .collect()
}

/// Serialise any serde structure to canonical JSON (stable object key ordering, compact format).
pub fn to_canonical_json_bytes<T>(value: &T) -> std::result::Result<Vec<u8>, JigError>
where
    T: Serialize,
{
    let mut json = serde_json::to_value(value)
        .map_err(|e| JigError::Serialization(format!("serialize to value: {e}")))?;
    canonicalize_value(&mut json);

    let mut buf = Vec::new();
    {
        let formatter = serde_json::ser::CompactFormatter {};
        let mut serializer = serde_json::Serializer::with_formatter(&mut buf, formatter);
        json.serialize(&mut serializer)
            .map_err(|e| JigError::Serialization(format!("serialize canonical json: {e}")))?;
    }
    Ok(buf)
}

fn canonicalize_value(value: &mut Value) {
    match value {
        Value::Object(map) => {
            let mut ordered: Vec<(String, Value)> = std::mem::take(map)
                .into_iter()
                .map(|(k, mut v)| {
                    canonicalize_value(&mut v);
                    (k, v)
                })
                .collect();
            ordered.sort_by(|a, b| a.0.cmp(&b.0));

            let mut new_map = Map::with_capacity(ordered.len());
            for (k, v) in ordered {
                new_map.insert(k, v);
            }
            *map = new_map;
        }
        Value::Array(arr) => {
            for item in arr {
                canonicalize_value(item);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_json_sorts_keys_recursively() {
        let value = json!({
            "b": 1,
            "a": {
                "z": 0,
                "y": 1
            }
        });

        let bytes = to_canonical_json_bytes(&value).expect("canonicalise");
        let as_str = String::from_utf8(bytes).expect("utf8");
        assert_eq!(as_str, r#"{"a":{"y":1,"z":0},"b":1}"#);
    }
}
