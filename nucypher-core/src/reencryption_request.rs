use alloc::boxed::Box;

use serde::{Deserialize, Serialize};
use umbral_pre::{Capsule, PublicKey};

use crate::address::Address;
use crate::hrac::HRAC;
use crate::key_frag::EncryptedKeyFrag;
use crate::serde::ProtocolObject;
use crate::treasure_map::TreasureMap;

/// A request for an Ursula to reencrypt for several capsules.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ReencryptionRequest {
    /// Policy HRAC.
    pub hrac: HRAC,
    /// Publisher's verifying key.
    pub publisher_verifying_key: PublicKey,
    /// Recipient's (Bob's) verifying key.
    pub bob_verifying_key: PublicKey,
    /// Key frag encrypted for the Ursula.
    pub encrypted_kfrag: EncryptedKeyFrag,
    /// Capsules to re-encrypt.
    pub capsules: Box<[Capsule]>,
}

impl ReencryptionRequest {
    /// Creates a new reencryption request.
    pub fn new(
        ursula_address: &Address,
        capsules: &[Capsule],
        treasure_map: &TreasureMap,
        bob_verifying_key: &PublicKey,
    ) -> Self {
        let (_address, encrypted_kfrag) = treasure_map
            .destinations
            .iter()
            .find(|(address, _ekfrag)| address == ursula_address)
            .unwrap();

        Self {
            hrac: treasure_map.hrac,
            publisher_verifying_key: treasure_map.publisher_verifying_key,
            bob_verifying_key: *bob_verifying_key,
            encrypted_kfrag: encrypted_kfrag.clone(),
            capsules: capsules.into(),
        }
    }
}

impl ProtocolObject for ReencryptionRequest {}
