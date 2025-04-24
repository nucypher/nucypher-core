use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    decrypt_original, encrypt, serde_bytes, Capsule, EncryptionError, PublicKey, SecretKey,
    Signature, Signer, VerifiedKeyFrag,
};

use crate::address::Address;
use crate::hrac::HRAC;
use crate::key_frag::{DecryptionError, EncryptedKeyFrag};
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};
use crate::RevocationOrder;

/// A structure containing `KeyFrag` objects encrypted for Ursulas chosen for this policy.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct TreasureMap {
    /// Threshold for successful re-encryption.
    pub threshold: u8,
    /// Policy HRAC.
    pub hrac: HRAC,
    /// Encrypted key frags assigned to target Ursulas.
    pub destinations: BTreeMap<Address, EncryptedKeyFrag>,
    /// A key to create encrypted messages under this policy.
    pub policy_encrypting_key: PublicKey,
    /// Publisher's verifying key.
    pub publisher_verifying_key: PublicKey,
}

impl TreasureMap {
    /// Create a new treasure map for a collection of ursulas and kfrags.
    ///
    /// Panics if `threshold` is set to 0,
    /// the number of assigned keyfrags is less than `threshold`,
    /// or if the addresses in `assigned_kfrags` repeat.
    pub fn new(
        signer: &Signer,
        hrac: &HRAC,
        policy_encrypting_key: &PublicKey,
        assigned_kfrags: impl IntoIterator<Item = (Address, (PublicKey, VerifiedKeyFrag))>,
        threshold: u8,
    ) -> Self {
        // Panic here since violation of this condition indicates a bug on the caller's side.
        assert!(threshold != 0, "threshold must be non-zero");

        // Encrypt each kfrag for an Ursula.
        let mut destinations = BTreeMap::new();
        for (ursula_address, (ursula_encrypting_key, verified_kfrag)) in assigned_kfrags.into_iter()
        {
            let encrypted_kfrag =
                EncryptedKeyFrag::new(signer, &ursula_encrypting_key, hrac, verified_kfrag);
            if destinations
                .insert(ursula_address, encrypted_kfrag)
                .is_some()
            {
                // This means there are repeating addresses in the mapping.
                // Panic here since violation of this condition indicates a bug on the caller's side.
                panic!(
                    "{}",
                    format!("Repeating address in assigned_kfrags: {:?}", ursula_address)
                )
            };
        }

        // Panic here since violation of this condition indicates a bug on the caller's side.
        assert!(
            destinations.len() >= threshold as usize,
            "threshold cannot be larger than the total number of shares"
        );

        Self {
            threshold,
            hrac: *hrac,
            destinations,
            policy_encrypting_key: *policy_encrypting_key,
            publisher_verifying_key: signer.verifying_key(),
        }
    }

    /// Encrypts the treasure map for Bob.
    pub fn encrypt(&self, signer: &Signer, recipient_key: &PublicKey) -> EncryptedTreasureMap {
        EncryptedTreasureMap::new(signer, recipient_key, self)
    }

    /// Makes revocation orders for all destinations in the treasure map.
    pub fn make_revocation_orders(&self, signer: &Signer) -> Vec<RevocationOrder> {
        self.destinations
            .iter()
            .map(|(address, ekfrag)| RevocationOrder::new(signer, address, ekfrag))
            .collect()
    }
}

impl ProtocolObjectInner<'_> for TreasureMap {
    fn brand() -> [u8; 4] {
        *b"TMap"
    }

    fn version() -> (u16, u16) {
        (3, 0)
    }

    fn unversioned_to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(&self)
    }

    fn unversioned_from_bytes(minor_version: u16, bytes: &[u8]) -> Option<Result<Self, String>> {
        if minor_version == 0 {
            Some(messagepack_deserialize(bytes))
        } else {
            None
        }
    }
}

impl ProtocolObject<'_> for TreasureMap {}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
struct AuthorizedTreasureMap {
    signature: Signature,
    treasure_map: TreasureMap,
}

impl AuthorizedTreasureMap {
    fn message_to_sign(recipient_key: &PublicKey, treasure_map: &TreasureMap) -> Vec<u8> {
        let mut message = recipient_key.to_compressed_bytes().to_vec();
        message.extend(treasure_map.to_bytes().iter());
        message
    }

    fn new(signer: &Signer, recipient_key: &PublicKey, treasure_map: &TreasureMap) -> Self {
        let message = Self::message_to_sign(recipient_key, treasure_map);
        let signature = signer.sign(&message);

        Self {
            signature,
            treasure_map: treasure_map.clone(),
        }
    }

    fn verify(
        self,
        recipient_key: &PublicKey,
        publisher_verifying_key: &PublicKey,
    ) -> Option<TreasureMap> {
        let message = Self::message_to_sign(recipient_key, &self.treasure_map);
        if !self.signature.verify(publisher_verifying_key, &message) {
            return None;
        }
        Some(self.treasure_map)
    }
}

impl ProtocolObjectInner<'_> for AuthorizedTreasureMap {
    fn brand() -> [u8; 4] {
        *b"AMap"
    }

    fn version() -> (u16, u16) {
        (3, 0)
    }

    fn unversioned_to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(&self)
    }

    fn unversioned_from_bytes(minor_version: u16, bytes: &[u8]) -> Option<Result<Self, String>> {
        if minor_version == 0 {
            Some(messagepack_deserialize(bytes))
        } else {
            None
        }
    }
}

impl ProtocolObject<'_> for AuthorizedTreasureMap {}

/// A treasure map encrypted for Bob.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedTreasureMap {
    capsule: Capsule,
    #[serde(with = "serde_bytes::as_base64")]
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
        let (capsule, ciphertext) = match encrypt(recipient_key, &authorized_tmap.to_bytes()) {
            Ok(result) => result,
            Err(err) => match err {
                // For now this is the only error that can happen during encryption,
                // and there's really no point in propagating it.
                EncryptionError::PlaintextTooLarge => panic!("encryption failed - out of memory?"),
            },
        };
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
    ) -> Result<TreasureMap, DecryptionError> {
        let auth_tmap_bytes = decrypt_original(sk, &self.capsule, &self.ciphertext)
            .map_err(DecryptionError::DecryptionFailed)?;
        let auth_tmap = AuthorizedTreasureMap::from_bytes(&auth_tmap_bytes)
            .map_err(DecryptionError::DeserializationFailed)?;
        auth_tmap
            .verify(&sk.public_key(), publisher_verifying_key)
            .ok_or(DecryptionError::VerificationFailed)
    }
}

impl ProtocolObjectInner<'_> for EncryptedTreasureMap {
    fn brand() -> [u8; 4] {
        *b"EMap"
    }

    fn version() -> (u16, u16) {
        (3, 0)
    }

    fn unversioned_to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(&self)
    }

    fn unversioned_from_bytes(minor_version: u16, bytes: &[u8]) -> Option<Result<Self, String>> {
        if minor_version == 0 {
            Some(messagepack_deserialize(bytes))
        } else {
            None
        }
    }
}

impl ProtocolObject<'_> for EncryptedTreasureMap {}
