use core::str::FromStr;

use ethereum_types::Address;

/// Converts a string with a checksummed Ethereum address into the canonical form (a byte array).
pub fn to_canonical_address(checksum_address: &str) -> Option<Address> {
    // TODO: check the checksum
    let hex_str = checksum_address.strip_prefix("0x")?;
    Address::from_str(hex_str).ok()
}

#[cfg(test)]
mod tests {
    use ethereum_types::Address;

    use super::to_canonical_address;

    #[test]
    fn test_checksum() {
        let checksum_address = "0xe0FC04FA2d34a66B779fd5CEe748268032a146c0";
        let address_reference =
            Address::from(b"\xe0\xfc\x04\xfa-4\xa6kw\x9f\xd5\xce\xe7H&\x802\xa1F\xc0");

        let address = to_canonical_address(&checksum_address).unwrap();
        assert_eq!(address, address_reference);
    }
}
