use alloc::boxed::Box;

use generic_array::sequence::Split;
use generic_array::GenericArray;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use typenum::U16;
use umbral_pre::serde::{serde_deserialize, serde_serialize, Representation};
use umbral_pre::{
    ConstructionError, DeserializableFromArray, HasTypeName, PublicKey, RepresentableAsArray,
    SerializableToArray,
};

use crate::serde::SerializableToBytes;

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
#[derive(PartialEq, Debug, Copy, Clone)]
pub struct HRAC([u8; 16]);

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

impl HasTypeName for HRAC {
    fn type_name() -> &'static str {
        "HRAC"
    }
}

impl RepresentableAsArray for HRAC {
    type Size = U16;
}

impl SerializableToArray for HRAC {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0.into()
    }
}

impl DeserializableFromArray for HRAC {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        // The size is checked statically by the method signature,
        // so `from_slice()` never fails.
        Ok(HRAC(*arr.as_ref()))
    }
}

impl Serialize for HRAC {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Hex)
    }
}

impl<'de> Deserialize<'de> for HRAC {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Hex)
    }
}

impl SerializableToBytes for HRAC {
    fn to_bytes(&self) -> Box<[u8]> {
        Box::<[u8]>::from(self.0.as_slice())
    }
}
