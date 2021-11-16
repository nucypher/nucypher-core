use alloc::boxed::Box;

use ethereum_types::Address;
use serde::{Deserialize, Serialize};
use umbral_pre::{Capsule, PublicKey};

use crate::hrac::HRAC;
use crate::key_frag::EncryptedKeyFrag;
use crate::treasure_map::TreasureMap;

/// A request for an Ursula to reencrypt for several capsules.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencryptionRequest {
    hrac: HRAC,
    publisher_verifying_key: PublicKey,
    bob_verifying_key: PublicKey,
    encrypted_kfrag: EncryptedKeyFrag,
    capsules: Box<[Capsule]>,
}

impl ReencryptionRequest {
    fn new(
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
