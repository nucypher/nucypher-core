use alloc::boxed::Box;
use alloc::vec::Vec;

use ethereum_types::Address;
use serde::{Deserialize, Serialize};
use umbral_pre::{
    decrypt_original, encrypt, Capsule, PublicKey, SecretKey, SerializableToArray, Signature,
    Signer, VerifiedKeyFrag,
};

use crate::hrac::HRAC;
use crate::key_frag::EncryptedKeyFrag;
use crate::serde::{standard_deserialize, standard_serialize};

pub enum TreasureMapError {
    IncorrectThresholdSize,
    TooFewDestinations,
}

/// A structure containing `KeyFrag` objects encrypted for Ursulas chosen for this policy.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct TreasureMap {
    /// Threshold for successful re-encryption.
    pub threshold: usize,
    /// Policy HRAC.
    pub hrac: HRAC,
    // TODO: HashMap requires `std`. Do we actually want `no_std` for this crate?
    // There seems to be a BTreeMap available for no_std environments,
    // but let's just use vector for now.
    /// Encrypted key frags assigned to target Ursulas.
    pub destinations: Vec<(Address, EncryptedKeyFrag)>,
    /// A key to create encrypted messages under this policy.
    pub policy_encrypting_key: PublicKey,
    /// Publisher's verifying key.
    pub publisher_verifying_key: PublicKey,
}

impl TreasureMap {
    /// Create a new treasure map for a collection of ursulas and kfrags.
    pub fn new(
        signer: &Signer,
        hrac: &HRAC,
        policy_encrypting_key: &PublicKey,
        // TODO: would be nice to enforce that checksum addresses are not repeated,
        // but there is no "map-like" trait in Rust, and a specific map class seems too restrictive...
        assigned_kfrags: &[(Address, PublicKey, VerifiedKeyFrag)],
        threshold: usize,
    ) -> Result<Self, TreasureMapError> {
        if !(1..=255).contains(&threshold) {
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
            let encrypted_kfrag =
                EncryptedKeyFrag::new(signer, ursula_encrypting_key, hrac, verified_kfrag).unwrap();
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

    /// Encrypts the treasure map for Bob.
    pub fn encrypt(&self, signer: &Signer, recipient_key: &PublicKey) -> EncryptedTreasureMap {
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

/// A treasure map encrypted for Bob.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTreasureMap {
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

    /// Decrypts and verifies the treasure map.
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        publisher_verifying_key: &PublicKey,
    ) -> Option<TreasureMap> {
        let plaintext = decrypt_original(sk, &self.capsule, &self.ciphertext).unwrap();
        let auth_tmap = standard_deserialize::<AuthorizedTreasureMap>(&plaintext);
        auth_tmap.verify(&sk.public_key(), publisher_verifying_key)
    }
}
