use generic_array::sequence::Split;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use typenum::U16;
use umbral_pre::{PublicKey, SerializableToArray};

use crate::serde::{serde_deserialize_as_bytes, serde_serialize_as_bytes};

/// "hashed resource access code".
///
/// A hash of:
/// * Publisher's verifying key
/// * Bob's verifying key
/// * the label
///
/// Publisher and Bob have all the information they need to construct this.
/// Ursula does not, so we share it with her.
///
/// This way, Bob can generate it and use it to find the TreasureMap.
#[derive(PartialEq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct HRAC(
    #[serde(
        serialize_with = "serde_serialize_as_bytes",
        deserialize_with = "serde_deserialize_as_bytes"
    )]
    [u8; 16],
);

impl HRAC {
    /// Creates a new HRAC.
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
