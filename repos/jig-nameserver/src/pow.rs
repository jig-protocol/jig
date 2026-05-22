//! Proof-of-Work helpers (simple Hashcash-style over blake3)

use blake3;

/// Compute the number of leading zero bits in a 32-byte hash
pub fn leading_zero_bits(hash: &[u8; 32]) -> u16 {
    let mut count: u16 = 0;
    for byte in hash.iter() {
        if *byte == 0 {
            count += 8;
            continue;
        }
        // Count leading zeros in this byte
        let mut b = *byte;
        let mut bits: u16 = 0;
        while (b & 0x80) == 0 {
            bits += 1;
            b <<= 1;
        }
        count += bits;
        break;
    }
    count
}

/// Verify PoW: keyed hash over canonical fields and nonce must have >= difficulty leading zero bits
pub fn verify_pow(
    server_secret: &str,
    challenge_id: &str,
    action: &str,
    subject: &str,
    scope: &str,
    nonce: &str,
    difficulty: u16,
) -> bool {
    let key = blake3::hash(server_secret.as_bytes());
    let payload = format!("{challenge_id}|{action}|{subject}|{scope}|{nonce}");
    let digest = blake3::keyed_hash(key.as_bytes(), payload.as_bytes());
    let bits = leading_zero_bits(digest.as_bytes());
    bits >= difficulty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leading_zero_bits_counts() {
        assert_eq!(leading_zero_bits(&[0u8; 32]), 256);
        // Simple sanity: 0x00 -> 8, 0x0f -> 4, 0xff -> 0
        let mut h = [0u8; 32];
        h[0] = 0x00;
        h[1] = 0xff;
        assert_eq!(leading_zero_bits(&h), 8);
        let mut h2 = [0u8; 32];
        h2[0] = 0x0f;
        assert_eq!(leading_zero_bits(&h2), 4);
        let mut h3 = [0u8; 32];
        h3[0] = 0xff;
        assert_eq!(leading_zero_bits(&h3), 0);
    }
}
