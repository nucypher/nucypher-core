use alloc::format;
use alloc::string::String;
use core::str::FromStr;

use ethers::{types::Address as Addr, utils::to_checksum};
use generic_array::{
    sequence::Split,
    typenum::{U12, U20},
    GenericArray,
};
use serde::{Deserialize, Serialize};
use sha3::{digest::Update, Digest, Keccak256};
use umbral_pre::{serde_bytes, PublicKey};

// We could use the third-party `ethereum_types::Address` here,
// but since it's just a wrapper around `[u8; 20]` it's not worth
// adding an extra dependency. Same for `PublicKeyAddress` - we're not burdening this crate
// with web3 primitives, it can be derived later using web3 crate if needed.

/// Represents an Ethereum address (20 bytes).
#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone, PartialOrd, Eq, Ord)]
pub struct Address(#[serde(with = "serde_bytes::as_hex")] [u8; Address::SIZE]);

impl Address {
    /// Number of bytes in an address.
    pub const SIZE: usize = 20;

    /// Creates an address from a fixed-length array.
    pub fn new(bytes: &[u8; Self::SIZE]) -> Self {
        Self(*bytes)
    }

    pub(crate) fn from_public_key(pk: &PublicKey) -> Self {
        // Canonical address is the last 20 bytes of keccak256 hash
        // of the uncompressed public key (without the header, so 64 bytes in total).
        let pk_bytes = pk.to_uncompressed_bytes();
        let digest = Keccak256::new().chain(&pk_bytes[1..]).finalize();

        let (_prefix, address): (GenericArray<u8, U12>, GenericArray<u8, U20>) = digest.split();

        Self(address.into())
    }

    /// Returns the EIP-55 checksummed representation of the address.
    pub fn to_checksum_address(&self) -> String {
        to_checksum(&Addr::from(self.0), None)
    }
}

impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s).map_err(|e| format!("Invalid hex string: {}", e))?;
        if bytes.len() != Self::SIZE {
            return Err(format!(
                "Invalid address length: expected {} bytes, got {} bytes",
                Self::SIZE,
                bytes.len()
            ));
        }
        let mut array = [0u8; Self::SIZE];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use umbral_pre::SecretKey;

    #[test]
    fn test_checksum_address() {
        // Test case from EIP-55
        let address_bytes = hex::decode("5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed").unwrap();
        let mut array = [0u8; 20];
        array.copy_from_slice(&address_bytes);
        let address = Address::new(&array);

        assert_eq!(
            address.to_checksum_address(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );

        // Test with all lowercase input
        let address_bytes2 = hex::decode("fb6916095ca1df60bb79ce92ce3ea74c37c5d359").unwrap();
        let mut array2 = [0u8; 20];
        array2.copy_from_slice(&address_bytes2);
        let address2 = Address::new(&array2);

        assert_eq!(
            address2.to_checksum_address(),
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
    }

    #[test]
    fn test_from_str() {
        let address_str = "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed";
        let address = Address::from_str(address_str).unwrap();
        assert_eq!(address.to_checksum_address(), address_str);
    }

    #[test]
    fn test_from_str_invalid_hex() {
        let address_str = "0x5aAzzzzzzz"; // 19 bytes
        let result = Address::from_str(address_str);
        assert!(result.unwrap_err().contains("Invalid hex string"));
    }

    #[test]
    fn test_from_str_invalid_length() {
        let address_str = "0x5aAeb6053F3E94C9b9A09f3366"; // too little bytes
        let result = Address::from_str(address_str);
        assert!(result.unwrap_err().contains("Invalid address length"));
    }

    #[test]
    fn test_from_public_key() {
        let public_key = SecretKey::random().public_key();
        let address_from_public_key = Address::from_public_key(&public_key);
        let address_from_str =
            Address::from_str(&address_from_public_key.to_checksum_address()).unwrap();
        assert_eq!(
            address_from_str.to_checksum_address(),
            address_from_public_key.to_checksum_address()
        );
    }
}
