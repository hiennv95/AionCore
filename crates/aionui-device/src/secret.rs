//! Random secrets and their stored form. Secrets are never kept or logged in
//! clear; only SHA-256 digests are compared, in constant time.

use sha2::{Digest, Sha256};

use crate::error::DeviceError;

/// Alphabet for hand-typed codes: no 0/O, 1/I/L.
const CODE_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], DeviceError> {
    let mut buf = [0u8; N];
    getrandom::getrandom(&mut buf).map_err(|e| DeviceError::Internal(format!("entropy source failed: {e}")))?;
    Ok(buf)
}

/// 256-bit secret as hex.
pub(crate) fn random_secret() -> Result<String, DeviceError> {
    Ok(hex::encode(random_bytes::<32>()?))
}

/// 8 characters from a 31-symbol alphabet (~39 bits), for typing by hand.
/// Bytes at or above the largest multiple of 31 are redrawn, so every symbol is
/// equally likely (a plain `% 31` favours the first 8 symbols).
pub(crate) fn random_code() -> Result<String, DeviceError> {
    const LEN: usize = 8;
    let n = CODE_ALPHABET.len();
    let limit = 256 - 256 % n;
    let mut code = String::with_capacity(LEN);
    while code.len() < LEN {
        for b in random_bytes::<16>()? {
            if usize::from(b) < limit && code.len() < LEN {
                code.push(CODE_ALPHABET[usize::from(b) % n] as char);
            }
        }
    }
    Ok(code)
}

/// Codes are case- and separator-insensitive: "abcd-2345" == "ABCD2345".
pub(crate) fn normalize_code(input: &str) -> String {
    input
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

pub(crate) fn digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// Constant-time equality of two digests.
pub(crate) fn digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_use_the_unambiguous_alphabet() {
        let code = random_code().unwrap();
        assert_eq!(code.len(), 8);
        assert!(code.bytes().all(|b| CODE_ALPHABET.contains(&b)));
    }

    #[test]
    fn code_normalization_ignores_case_and_separators() {
        assert_eq!(normalize_code("abcd-2345"), "ABCD2345");
        assert_eq!(normalize_code(" AB CD 23 45 "), "ABCD2345");
    }

    #[test]
    fn digest_equality() {
        assert!(digest_eq(&digest("a"), &digest("a")));
        assert!(!digest_eq(&digest("a"), &digest("b")));
        assert_eq!(random_secret().unwrap().len(), 64);
    }
}
