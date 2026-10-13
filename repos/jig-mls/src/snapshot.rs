//! Byte snapshots of openmls key-value storage.
//!
//! openmls keeps group state in a storage provider. Both roles use the
//! in-memory provider and persist it as one blob: the server in a SQLite
//! column, the client in a file. The format is private to this crate —
//! a count, then length-prefixed key/value pairs in key order, so the same
//! state always snapshots to the same bytes.

use openmls_memory_storage::MemoryStorage;

use crate::{MlsError, Result};

const MAGIC: &[u8; 6] = b"JMLS\x00\x01";

pub fn encode(storage: &MemoryStorage) -> Vec<u8> {
    let values = storage.values.read().expect("MLS storage lock poisoned");
    let mut entries: Vec<_> = values.iter().collect();
    entries.sort();
    let mut out = Vec::with_capacity(16 + entries.len() * 64);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(entries.len() as u64).to_le_bytes());
    for (k, v) in entries {
        out.extend_from_slice(&(k.len() as u64).to_le_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(&(v.len() as u64).to_le_bytes());
        out.extend_from_slice(v);
    }
    out
}

pub fn decode_into(bytes: &[u8], storage: &MemoryStorage) -> Result<()> {
    let mut rest = bytes
        .strip_prefix(MAGIC.as_slice())
        .ok_or_else(|| MlsError::Malformed("not an MLS state snapshot".to_string()))?;
    let count = take_u64(&mut rest)?;
    let mut values = storage.values.write().expect("MLS storage lock poisoned");
    for _ in 0..count {
        let k_len = take_u64(&mut rest)? as usize;
        let k = take(&mut rest, k_len)?.to_vec();
        let v_len = take_u64(&mut rest)? as usize;
        let v = take(&mut rest, v_len)?.to_vec();
        values.insert(k, v);
    }
    if !rest.is_empty() {
        return Err(MlsError::Malformed(
            "trailing bytes after MLS state snapshot".to_string(),
        ));
    }
    Ok(())
}

pub fn decode(bytes: &[u8]) -> Result<MemoryStorage> {
    let storage = MemoryStorage::default();
    decode_into(bytes, &storage)?;
    Ok(storage)
}

fn take<'a>(rest: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if rest.len() < n {
        return Err(MlsError::Malformed(
            "truncated MLS state snapshot".to_string(),
        ));
    }
    let (head, tail) = rest.split_at(n);
    *rest = tail;
    Ok(head)
}

fn take_u64(rest: &mut &[u8]) -> Result<u64> {
    let b = take(rest, 8)?;
    Ok(u64::from_le_bytes(b.try_into().expect("8 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_round_trip_and_are_deterministic() {
        let s = MemoryStorage::default();
        {
            let mut v = s.values.write().unwrap();
            v.insert(b"b".to_vec(), b"2".to_vec());
            v.insert(b"a".to_vec(), vec![]);
        }
        let bytes = encode(&s);
        let back = decode(&bytes).unwrap();
        assert_eq!(*back.values.read().unwrap(), *s.values.read().unwrap());
        assert_eq!(encode(&back), bytes);
    }

    #[test]
    fn truncated_snapshots_are_refused() {
        let s = MemoryStorage::default();
        s.values
            .write()
            .unwrap()
            .insert(b"k".to_vec(), b"v".to_vec());
        let bytes = encode(&s);
        assert!(decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(decode(b"nope").is_err());
    }
}
