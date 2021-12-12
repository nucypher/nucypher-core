use core::str::FromStr;

use ethereum_types::Address as ETAddress;
use generic_array::GenericArray;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use typenum::U20;
use umbral_pre::serde::{serde_deserialize, serde_serialize, Representation};
use umbral_pre::{
    ConstructionError, DeserializableFromArray, HasTypeName, RepresentableAsArray,
    SerializableToArray,
};

// We have to wrap the third-party Address in a newtype since the serde implementation
// for `ethereum_types::Address` serializes it as a hex string even in binary formats,
// and we want to serialize it as binary.
// We could just make our own type, but the goal here is to make it possible to connect
// with `web3` crate later, which uses the same type.

/// Represents an Ethereum address (20 bytes).
#[derive(PartialEq, Debug, Copy, Clone, PartialOrd, Eq, Ord)]
pub struct Address(ETAddress);

impl Address {
    /// Converts a string with a checksummed Ethereum address into the canonical form (a byte array).
    pub fn from_checksum_address(checksum_address: &str) -> Option<Address> {
        // TODO: check the checksum
        let hex_str = checksum_address.strip_prefix("0x")?;
        ETAddress::from_str(hex_str).ok().map(Address)
    }
}

impl HasTypeName for Address {
    fn type_name() -> &'static str {
        "Address"
    }
}

impl RepresentableAsArray for Address {
    type Size = U20;
}

impl SerializableToArray for Address {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0.to_fixed_bytes().into()
    }
}

impl DeserializableFromArray for Address {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        // The size is checked statically by the method signature,
        // so `from_slice()` never fails.
        Ok(Address(ETAddress::from_slice(arr)))
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Hex)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Hex)
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::Address;
    use ethereum_types::Address as ETAddress;

    #[test]
    fn test_checksum() {
        let checksum_address = "0xe0FC04FA2d34a66B779fd5CEe748268032a146c0";
        let address_reference = Address(ETAddress::from(
            b"\xe0\xfc\x04\xfa-4\xa6kw\x9f\xd5\xce\xe7H&\x802\xa1F\xc0",
        ));

        let address = Address::from_checksum_address(&checksum_address).unwrap();
        assert_eq!(address, address_reference);
    }
}
