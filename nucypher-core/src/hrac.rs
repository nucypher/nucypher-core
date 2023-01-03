use core::fmt;

use generic_array::sequence::Split;
use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use signature::digest::Update;
use typenum::U16;
use umbral_pre::{serde_bytes, PublicKey, SerializableToArray};

/// "hashed resource access code".
///
/// A hash of:
/// * Publisher's verifying key
/// * Bob's verifying key
/// * the label
///
/// Publisher and Bob have all the information they need to construct this.
/// Ursula does not, so we share it with her.
#[allow(clippy::upper_case_acronyms)]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Serialize, Deserialize)]
pub struct HRAC(#[serde(with = "serde_bytes::as_hex")] [u8; HRAC::SIZE]);

impl HRAC {
    /// The size of HRAC in bytes.
    pub const SIZE: usize = 16;

    /// Creates a new HRAC.
    pub fn new(
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        label: &[u8],
    ) -> Self {
        let digest = Keccak256::new()
            .chain(publisher_verifying_key.to_array())
            .chain(bob_verifying_key.to_array())
            .chain(label)
            .finalize();

        // No problem with hardcoding here, since the size will be checked in compile-time
        let (hrac, _rest): (GenericArray<u8, U16>, GenericArray<u8, _>) = digest.split();
        Self(hrac.into())
    }
}

impl From<[u8; HRAC::SIZE]> for HRAC {
    fn from(bytes: [u8; HRAC::SIZE]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for HRAC {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl fmt::Display for HRAC {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hex_repr = hex::encode(&self.0[..8]);
        write!(f, "HRAC:{}...", hex_repr)
    }
}
