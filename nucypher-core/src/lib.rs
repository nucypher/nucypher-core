//! A collection of objects defining the protocol for NyCypher nodes (Ursulas).

#![doc(html_root_url = "https://docs.rs/nucypher-core")]
#![forbid(unsafe_code)]
#![warn(missing_docs, rust_2018_idioms, unused_qualifications)]
#![no_std]

extern crate alloc;

mod address;
mod arrays_as_bytes;
mod fleet_state;
mod hrac;
mod key_frag;
mod message_kit;
mod node_metadata;
mod reencryption;
mod retrieval_kit;
mod revocation_order;
mod treasure_map;
mod versioning;

pub use address::{Address, ADDRESS_SIZE};
pub use fleet_state::FleetStateChecksum;
pub use hrac::HRAC;
pub use key_frag::EncryptedKeyFrag;
pub use message_kit::MessageKit;
pub use node_metadata::{
    MetadataRequest, MetadataResponse, MetadataResponsePayload, NodeMetadata, NodeMetadataPayload,
    RECOVERABLE_SIGNATURE_SIZE,
};
pub use reencryption::{ReencryptionRequest, ReencryptionResponse};
pub use retrieval_kit::RetrievalKit;
pub use revocation_order::RevocationOrder;
pub use treasure_map::{EncryptedTreasureMap, TreasureMap};
pub use versioning::ProtocolObject;

// Re-export crates so that the users don't have to version-match.
pub use k256;
pub use umbral_pre;
pub use x509_certificate;
