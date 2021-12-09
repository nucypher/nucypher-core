use core::convert::TryInto;

use serde::{Deserialize, Serialize};

use crate::arrays_as_bytes;

// We could use the third-party `ethereum_types::Address` here,
// but it has an inefficient `serde` implementation (serializes as hex instead of bytes).
// So for simplicity we just use our own type since we only need the size check.
// Later a conversion method can be easily defined to/from `ethereum_types::Address`.

/// Represents an Ethereum address (20 bytes).
#[derive(PartialEq, Debug, Serialize, Deserialize, Copy, Clone, PartialOrd, Eq, Ord)]
pub struct Address(#[serde(with = "arrays_as_bytes")] [u8; 20]);

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
mod tests {
    use super::Address;
    use ethereum_types::Address as ETAddress;

    #[test]
    fn test_checksum() {
        let checksum_address = "0xe0FC04FA2d34a66B779fd5CEe748268032a146c0";
        let address_reference = Address(ETAddress::from(
            b"\xe0\xfc\x04\xfa-4\xa6kw\x9f\xd5\xce\xe7H&\x802\xa1F\xc0",
        ));

        let address = to_canonical_address(checksum_address).unwrap();
        assert_eq!(address, address_reference);
    }
}
