use alloc::boxed::Box;
use alloc::vec::Vec;

use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use typenum::U20;
use umbral_pre::{PublicKey, SerializableToArray, Signature, Signer, VerifiedKeyFrag};

use crate::authorized_kfrag::AuthorizedKeyFrag;
use crate::hrac::HRAC;
use crate::message_kit::MessageKit;
use crate::serde::{serde_deserialize_bytes_as_hex, serde_serialize_bytes_as_hex};

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
struct ChecksumAddress(
    #[serde(
        serialize_with = "serde_serialize_bytes_as_hex",
        deserialize_with = "serde_deserialize_bytes_as_hex"
    )]
    GenericArray<u8, U20>,
);

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
struct PublicUrsula {
    checksum_address: ChecksumAddress,
    encrypting_key: PublicKey,
}

enum TreasureMapError {
    IncorrectThresholdSize,
    TooFewDestinations,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
struct TreasureMap {
    threshold: usize,
    hrac: HRAC,
    // TODO: HashMap requires `std`. Do we actually want `no_std` for this crate?
    // There seems to be a BTreeMap available for no_std environments,
    // but let's just use vector for now.
    destinations: Vec<(ChecksumAddress, MessageKit)>,
}

// We need to pick some serialization method of the multitude Serde provides.
// Using MessagePack for now.
fn standard_serialize<T: Serialize>(obj: &T) -> Box<[u8]> {
    rmp_serde::to_vec(obj).unwrap().into_boxed_slice()
}

impl TreasureMap {
    /// Create a new treasure map for a collection of ursulas and kfrags.
    pub fn new(
        hrac: &HRAC,
        signer: &Signer,
        ursulas: &[PublicUrsula],
        verified_kfrags: &[VerifiedKeyFrag],
        threshold: usize,
    ) -> Result<Self, TreasureMapError> {
        if threshold < 1 || threshold > 255 {
            return Err(TreasureMapError::IncorrectThresholdSize);
        }

        if ursulas.len() < threshold {
            return Err(TreasureMapError::TooFewDestinations);
        }

        // Encrypt each kfrag for an Ursula.
        let mut destinations = Vec::new();
        for (ursula, verified_kfrag) in ursulas.iter().zip(verified_kfrags) {
            let akfrag = AuthorizedKeyFrag::new(hrac, verified_kfrag, signer);
            let encrypted_kfrag = MessageKit::new(
                &ursula.encrypting_key,
                &standard_serialize(&akfrag),
                signer,
                true,
            )
            .unwrap();
            destinations.push((ursula.checksum_address, encrypted_kfrag));
        }

        Ok(Self {
            threshold,
            hrac: *hrac,
            destinations,
        })
    }
}

#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
struct BlockchainSignature;

trait BlockchainSigner {
    fn sign(&self, message: &[u8]) -> BlockchainSignature;
}

struct EncryptedTreasureMap {
    hrac: HRAC,
    public_signature: Signature,
    encrypted_tmap: MessageKit,
    // TODO: use a special type for it?
    blockchain_signature: BlockchainSignature,
}

impl EncryptedTreasureMap {
    fn new<T: BlockchainSigner>(
        treasure_map: &TreasureMap,
        publisher_stamp: &Signer,
        bob_encrypting_key: &PublicKey,
        blockchain_signer: Option<T>,
    ) -> Self {
        // TODO: `publisher` here can be different from the one in TreasureMap, it seems.
        // Do we ever cross-check them? Do we want to enforce them to be the same?

        let encrypted_tmap = MessageKit::new(
            &bob_encrypting_key,
            &standard_serialize(&treasure_map),
            publisher_stamp,
            true,
        )
        .unwrap();

        let public_signature = publisher_stamp.sign(
            &[
                &publisher_stamp.verifying_key().to_array(),
                treasure_map.hrac.as_ref(),
            ]
            .concat(),
        );

        let blockchain_signature = match blockchain_signer {
            Some(signer) => signer.sign(
                &[
                    &public_signature.to_array(),
                    treasure_map.hrac.as_ref(),
                    &standard_serialize(&encrypted_tmap),
                ]
                .concat(),
            ),
            None => BlockchainSignature,
        };

        Self {
            hrac: treasure_map.hrac,
            public_signature,
            encrypted_tmap,
            blockchain_signature,
        }
    }
}
