//! A collection of objects defining the protocol for NyCypher nodes (Ursulas).

#![doc(html_root_url = "https://docs.rs/nucypher-core")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![no_std]

extern crate alloc;

mod access_control;
mod address;
mod conditions;
mod dkg;
mod fleet_state;
mod hrac;
mod key_frag;
mod message_kit;
mod node_metadata;
mod reencryption;
mod retrieval_kit;
mod revocation_order;
mod secret_box;
mod threshold_message_kit;
mod treasure_map;
mod versioning;
#[cfg(feature = "test_vectors")]
pub mod test_vectors;

/// Error returned by various `verify()` methods in the crate.
pub struct VerificationError;

pub use access_control::{encrypt_for_dkg, AccessControlPolicy, AuthenticatedData};

pub use address::Address;
pub use conditions::{Conditions, Context};
pub use dkg::{
    session::{SessionSecretFactory, SessionSharedSecret, SessionStaticKey, SessionStaticSecret},
    DecryptionError, EncryptedThresholdDecryptionRequest, EncryptedThresholdDecryptionResponse,
    EncryptionError, ThresholdDecryptionRequest, ThresholdDecryptionResponse,
};
pub use fleet_state::FleetStateChecksum;
pub use hrac::HRAC;
pub use key_frag::EncryptedKeyFrag;
pub use message_kit::MessageKit;
pub use node_metadata::{
    MetadataRequest, MetadataResponse, MetadataResponsePayload, NodeMetadata, NodeMetadataPayload,
};
pub use reencryption::{ReencryptionRequest, ReencryptionResponse};
pub use retrieval_kit::RetrievalKit;
pub use revocation_order::RevocationOrder;
pub use threshold_message_kit::ThresholdMessageKit;
pub use treasure_map::{EncryptedTreasureMap, TreasureMap};
pub use versioning::ProtocolObject;
#[cfg(feature = "test_vectors")]
pub use test_vectors::{TestVector, generate_test_vectors};

// Re-export umbral_pre so that the users don't have to version-match.
pub use umbral_pre;

// Re-export ferveo so that the users don't have to version-match.
pub use ferveo;
