use alloc::boxed::Box;
use alloc::vec::Vec;

use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use typenum::U20;
use umbral_pre::{
    decrypt_original, encrypt, Capsule, PublicKey, SecretKey, SerializableToArray, Signature,
    Signer, VerifiedKeyFrag,
};

use crate::hrac::HRAC;
use crate::key_frag::{AuthorizedKeyFrag, EncryptedKeyFrag};
use crate::serde::{
    serde_deserialize_bytes_as_hex, serde_serialize_bytes_as_hex, standard_deserialize,
    standard_serialize,
};

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct ChecksumAddress(
    #[serde(
        serialize_with = "serde_serialize_bytes_as_hex",
        deserialize_with = "serde_deserialize_bytes_as_hex"
    )]
    GenericArray<u8, U20>,
);

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub(crate) struct PublicUrsula {
    checksum_address: ChecksumAddress,
    encrypting_key: PublicKey,
}

pub(crate) enum TreasureMapError {
    IncorrectThresholdSize,
    TooFewDestinations,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TreasureMap {
    threshold: usize,
    pub(crate) hrac: HRAC,
    // TODO: HashMap requires `std`. Do we actually want `no_std` for this crate?
    // There seems to be a BTreeMap available for no_std environments,
    // but let's just use vector for now.
    pub(crate) destinations: Vec<(ChecksumAddress, EncryptedKeyFrag)>,
    policy_encrypting_key: PublicKey,
    pub(crate) publisher_verifying_key: PublicKey,
}

impl TreasureMap {
    /// Create a new treasure map for a collection of ursulas and kfrags.
    pub fn new(
        signer: &Signer,
        hrac: &HRAC,
        policy_encrypting_key: &PublicKey,
        // TODO: would be nice to enforce that checksum addresses are not repeated,
        // but there is no "map-like" trait in Rust, and a specific map class seems too restrictive...
        assigned_kfrags: &[(ChecksumAddress, PublicKey, VerifiedKeyFrag)],
        threshold: usize,
    ) -> Result<Self, TreasureMapError> {
        if threshold < 1 || threshold > 255 {
            return Err(TreasureMapError::IncorrectThresholdSize);
        }

        if assigned_kfrags.len() < threshold {
            return Err(TreasureMapError::TooFewDestinations);
        }

        // Encrypt each kfrag for an Ursula.
        let mut destinations = Vec::new();
        for (ursula_checksum_address, ursula_encrypting_key, verified_kfrag) in
            assigned_kfrags.iter()
        {
            let akfrag = AuthorizedKeyFrag::new(signer, hrac, verified_kfrag);
            let encrypted_kfrag = EncryptedKeyFrag::new(&ursula_encrypting_key, &akfrag).unwrap();
            destinations.push((*ursula_checksum_address, encrypted_kfrag));
        }

        Ok(Self {
            threshold,
            hrac: *hrac,
            destinations,
            policy_encrypting_key: *policy_encrypting_key,
            publisher_verifying_key: signer.verifying_key(),
        })
    }

    fn encrypt(&self, signer: &Signer, recipient_key: &PublicKey) -> EncryptedTreasureMap {
        EncryptedTreasureMap::new(signer, recipient_key, self)
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
struct AuthorizedTreasureMap {
    signature: Signature,
    treasure_map: TreasureMap,
}

impl AuthorizedTreasureMap {
    fn new(signer: &Signer, recipient_key: &PublicKey, treasure_map: &TreasureMap) -> Self {
        let mut message = recipient_key.to_array().to_vec();
        message.extend(standard_serialize(&treasure_map).iter());

        let signature = signer.sign(&message);

        Self {
            signature,
            treasure_map: treasure_map.clone(),
        }
    }

    fn verify(
        &self,
        recipient_key: &PublicKey,
        publisher_verifying_key: &PublicKey,
    ) -> Option<TreasureMap> {
        let mut message = recipient_key.to_array().to_vec();
        message.extend(standard_serialize(&self.treasure_map).iter());

        if !self.signature.verify(publisher_verifying_key, &message) {
            return None;
        }
        Some(self.treasure_map.clone())
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
struct EncryptedTreasureMap {
    capsule: Capsule,
    ciphertext: Box<[u8]>,
}

impl EncryptedTreasureMap {
    fn new(signer: &Signer, recipient_key: &PublicKey, treasure_map: &TreasureMap) -> Self {
        // TODO: using Umbral for encryption to avoid introducing more crypto primitives.
        // Most probably it is an overkill, unless it can be used somehow
        // for Ursula-to-Ursula "baton passing".

        // TODO: `publisher` here can be different from the one in TreasureMap, it seems.
        // Do we ever cross-check them? Do we want to enforce them to be the same?

        let authorized_tmap = AuthorizedTreasureMap::new(signer, recipient_key, treasure_map);
        let (capsule, ciphertext) =
            encrypt(recipient_key, &standard_serialize(&authorized_tmap)).unwrap();

        Self {
            capsule,
            ciphertext,
        }
    }

    pub fn decrypt(&self, sk: &SecretKey) -> AuthorizedTreasureMap {
        let plaintext = decrypt_original(sk, &self.capsule, &self.ciphertext).unwrap();
        standard_deserialize::<AuthorizedTreasureMap>(&plaintext)
    }
}
