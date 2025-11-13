use alloc::format;
use alloc::string::String;
use core::fmt;
use primitive_types::U256;
use serde::{Deserialize, Serialize};

/// A wrapper around `U256`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Uint256(pub U256);

impl fmt::Display for Uint256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Allows easy creation of `Uint256` from a `u64`. (this is mainly for testing convenience)
impl From<u64> for Uint256 {
    fn from(x: u64) -> Self {
        Uint256(U256::from(x))
    }
}

impl Uint256 {
    /// Creates a `Uint256` from a decimal string representation.
    pub fn from_dec_str(s: &str) -> Result<Self, String> {
        U256::from_dec_str(s)
            .map(Uint256)
            .map_err(|e| format!("Failed to parse U256 from decimal string: {}", e))
    }

    /// Converts the `Uint256` to a big-endian byte array.
    pub fn to_be_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        self.0.write_as_big_endian(&mut bytes);
        bytes
    }

    /// Creates a `Uint256` from a big-endian byte array.
    pub fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Uint256(U256::from_big_endian(&bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::Uint256;
    use alloc::string::ToString;

    #[test]
    fn test_uint256_to_string() {
        let value = Uint256::from(123456789u64);
        assert_eq!(value.to_string(), "123456789");
    }

    #[test]
    fn test_uint256_from_dec_str() {
        // valid case
        let str_value = "123456789";
        let value = Uint256::from_dec_str(str_value).unwrap();
        assert_eq!(value.to_string(), str_value);

        // large value
        let large_value_str =
            "14232009753527178202470101164636639162606829069286674824179796927290118780634";
        let large_value = Uint256::from_dec_str(large_value_str).unwrap();
        assert_eq!(large_value.to_string(), large_value_str);

        // invalid case
        let result = Uint256::from_dec_str("invalid_number");
        assert!(result.is_err());
    }

    #[test]
    fn test_uint256_from() {
        let value = Uint256::from(42);
        assert_eq!(value.to_string(), "42");
        assert_eq!(value, Uint256::from_dec_str("42").unwrap());
    }

    #[test]
    fn test_uint256_be_bytes_conversion() {
        let original = Uint256::from(123456789u64);
        let bytes = original.to_be_bytes();
        let reconstructed = Uint256::from_be_bytes(bytes);
        assert_eq!(original, reconstructed);
    }
}
