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
mod prim_types;
mod reencryption;
mod retrieval_kit;
mod revocation_order;
mod secret_box;
mod session;
mod signature_request;
mod test_utils;
mod threshold_message_kit;
mod treasure_map;
mod versioning;

/// Error returned by various `verify()` methods in the crate.
pub struct VerificationError;

pub use access_control::{encrypt_for_dkg, AccessControlPolicy, AuthenticatedData};

pub use address::Address;
pub use conditions::{Conditions, Context};
pub use dkg::{
    EncryptedThresholdDecryptionRequest, EncryptedThresholdDecryptionResponse,
    ThresholdDecryptionRequest, ThresholdDecryptionResponse,
};
pub use fleet_state::FleetStateChecksum;
pub use hrac::HRAC;
pub use key_frag::EncryptedKeyFrag;
pub use message_kit::MessageKit;
pub use node_metadata::{
    MetadataRequest, MetadataResponse, MetadataResponsePayload, NodeMetadata, NodeMetadataPayload,
};
pub use prim_types::Uint256;
pub use reencryption::{ReencryptionRequest, ReencryptionResponse};
pub use retrieval_kit::RetrievalKit;
pub use revocation_order::RevocationOrder;
pub use session::{
    key::{SessionSecretFactory, SessionSharedSecret, SessionStaticKey, SessionStaticSecret},
    DecryptionError, EncryptionError,
};
pub use signature_request::{
    deserialize_signature_request, AAVersion, BaseSignatureRequest, DirectSignatureRequest,
    EncryptedThresholdSignatureRequest, EncryptedThresholdSignatureResponse, PackedUserOperation,
    PackedUserOperationSignatureRequest, SignatureRequestType, SignatureResponse, UserOperation,
    UserOperationSignatureRequest,
};
pub use threshold_message_kit::ThresholdMessageKit;
pub use treasure_map::{EncryptedTreasureMap, TreasureMap};
pub use versioning::ProtocolObject;

// Re-export umbral_pre so that the users don't have to version-match.
pub use umbral_pre;

// Re-export ferveo so that the users don't have to version-match.
pub use ferveo;
