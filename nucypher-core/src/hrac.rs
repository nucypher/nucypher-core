use generic_array::sequence::Split;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use typenum::U16;
use umbral_pre::{PublicKey, SerializableToArray};

use crate::serde::{serde_deserialize_bytes_as_hex, serde_serialize_bytes_as_hex};

type HracSize = U16;

#[derive(PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct HRAC(
    #[serde(
        serialize_with = "serde_serialize_bytes_as_hex",
        deserialize_with = "serde_deserialize_bytes_as_hex"
    )]
    GenericArray<u8, HracSize>,
);

impl HRAC {
    pub fn new(
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        label: &[u8],
    ) -> Self {
        let digest = Sha3_256::new()
            .chain(&publisher_verifying_key.to_array())
            .chain(&bob_verifying_key.to_array())
            .chain(label)
            .finalize();

        let (hrac, _rest): (GenericArray<u8, HracSize>, GenericArray<u8, _>) = digest.split();
        Self(hrac)
    }
}

impl AsRef<[u8]> for HRAC {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
