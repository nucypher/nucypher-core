use core::convert::TryInto;

use serde::{Deserialize, Serialize};

use crate::serde::{serde_deserialize_as_bytes, serde_serialize_as_bytes};

// We could use the third-party `ethereum_types::Address` here,
// but it has an inefficient `serde` implementation (serializes as hex instead of bytes).
// So for simplicity we just use our own type since we only need the size check.
// Later a conversion method can be easily defined to/from `ethereum_types::Address`.

/// Represents an Ethereum address (20 bytes).
#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone, PartialOrd, Eq, Ord)]
pub struct Address(
    #[serde(
        serialize_with = "serde_serialize_as_bytes",
        deserialize_with = "serde_deserialize_as_bytes"
    )]
    [u8; 20],
);

impl Address {
    /// Attempts to create an address from a byte slice.
    /// Fails if the size of the slice is incorrect.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Address)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
