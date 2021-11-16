use generic_array::sequence::Split;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use typenum::{Unsigned, U16};
use umbral_pre::{PublicKey, SerializableToArray};

#[derive(PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct HRAC([u8; 16]);

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

        // No problem with hardcoding here, since the size will be checked in compile-time
        let (hrac, _rest): (GenericArray<u8, U16>, GenericArray<u8, _>) = digest.split();
        Self(hrac.into())
    }
}

impl AsRef<[u8]> for HRAC {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
