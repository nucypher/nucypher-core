use generic_array::{
    sequence::Split,
    typenum::{U12, U20},
    GenericArray,
};
use serde::{Deserialize, Serialize};
use sha3::{digest::Update, Digest, Keccak256};
use umbral_pre::{serde_bytes, PublicKey};

// We could use the third-party `ethereum_types::Address` here,
// but it has an inefficient `serde` implementation (serializes as hex instead of bytes).
// So for simplicity we just use our own type since we only need the size check.
// Later a conversion method can be easily defined to/from `ethereum_types::Address`.

/// Represents an Ethereum address (20 bytes).
#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone, PartialOrd, Eq, Ord)]
pub struct Address(#[serde(with = "serde_bytes::as_hex")] [u8; Address::SIZE]);

impl Address {
    /// Size of canonical Ethereum address, in bytes.
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
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Address> for [u8; Address::SIZE] {
    fn from(address: Address) -> [u8; Address::SIZE] {
        address.0
    }
}
