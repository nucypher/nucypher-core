use alloc::string::String;

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
        let hex_address = hex::encode(self.0);
        let hash = Keccak256::digest(hex_address.as_bytes());
        
        let mut result = String::with_capacity(42);
        result.push_str("0x");
        
        for (i, ch) in hex_address.chars().enumerate() {
            if ch.is_alphabetic() {
                let hash_byte = hash[i / 2];
                let hash_nibble = if i % 2 == 0 {
                    hash_byte >> 4
                } else {
                    hash_byte & 0x0f
                };
                
                if hash_nibble >= 8 {
                    result.push(ch.to_ascii_uppercase());
                } else {
                    result.push(ch);
                }
            } else {
                result.push(ch);
            }
        }
        
        result
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
}
