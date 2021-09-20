use alloc::boxed::Box;

use serde::{Deserialize, Serialize};
use umbral_pre::{Capsule, PublicKey};

use crate::hrac::HRAC;
use crate::message_kit::MessageKit;
use crate::treasure_map::{ChecksumAddress, TreasureMap};

/// A request for an Ursula to reencrypt for several capsules.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencryptionRequest {
    hrac: HRAC,
    alice_verifying_key: PublicKey,
    bob_verifying_key: PublicKey,
    encrypted_kfrag: MessageKit,
    capsules: Box<[Capsule]>,
}

impl ReencryptionRequest {
    fn new(
        capsules: &[Capsule],
        ursula_address: &ChecksumAddress,
        treasure_map: &TreasureMap,
        alice_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
    ) -> Self {
        let (_address, encrypted_kfrag) = treasure_map
            .destinations
            .iter()
            .find(|(address, _ekfrag)| address == ursula_address)
            .unwrap();

        Self {
            hrac: treasure_map.hrac,
            alice_verifying_key: *alice_verifying_key,
            bob_verifying_key: *bob_verifying_key,
            encrypted_kfrag: encrypted_kfrag.clone(),
            capsules: capsules.into(),
        }
    }
}
