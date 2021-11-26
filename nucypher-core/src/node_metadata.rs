use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use ethereum_types::Address;
use serde::{Deserialize, Serialize};
use umbral_pre::{PublicKey, Signature, Signer};

use crate::fleet_state::FleetStateChecksum;
use crate::serde::standard_serialize;

/// Node metadata.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadataPayload {
    pub public_address: Address,
    pub domain: String,
    pub timestamp_epoch: u32,
    pub verifying_key: PublicKey,
    pub encrypting_key: PublicKey,
    pub certificate_bytes: Box<[u8]>, // serialized SSL certificate in PEM format
    pub host: String,
    pub port: u16,
    pub decentralized_identity_evidence: Option<Box<[u8]>>, // TODO: make its own type?
}

impl NodeMetadataPayload {}

/// Signed node metadata.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadata {
    signature: Signature,
    pub(crate) payload: NodeMetadataPayload,
}

impl NodeMetadata {
    /// Creates and signs a new metadata object.
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        Self {
            signature: signer.sign(&standard_serialize(&payload)),
            payload: payload.clone(),
        }
    }

    /// Verifies signed node metadata and returns the contained payload.
    pub fn verify(&self) -> Option<NodeMetadataPayload> {
        // Note: in order for this to make sense, `verifying_key` must be checked independently.
        // Currently it is done in `validate_worker()` (using `decentralized_identity_evidence`)
        // TODO: do this on deserialization?
        if self.signature.verify(
            &self.payload.verifying_key,
            &standard_serialize(&self.payload),
        ) {
            Some(self.payload.clone())
        } else {
            None
        }
    }
}

/// A request for metadata exchange.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct MetadataRequest {
    fleet_state_checksum: FleetStateChecksum,
    announce_nodes: Option<Box<[NodeMetadata]>>,
}

impl MetadataRequest {
    /// Creates a new request.
    pub fn new(
        fleet_state_checksum: &FleetStateChecksum,
        announce_nodes: Option<&[NodeMetadata]>,
    ) -> Self {
        let maybe_nodes = announce_nodes.map(|nodes| nodes.to_vec());
        Self {
            fleet_state_checksum: fleet_state_checksum.clone(),
            announce_nodes: maybe_nodes.map(|nodes| nodes.into_boxed_slice()),
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct VerifiedMetadataResponse {
    this_node: Option<NodeMetadata>,
    other_nodes: Option<Box<[NodeMetadata]>>,
}

impl VerifiedMetadataResponse {
    pub fn new(this_node: Option<&NodeMetadata>, other_nodes: Option<&[NodeMetadata]>) -> Self {
        Self {
            this_node: this_node.cloned(),
            other_nodes: other_nodes.map(|nodes| nodes.to_vec().into_boxed_slice()),
        }
    }
}

/// A response returned by an Ursula containing known node metadata.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct MetadataResponse {
    signature: Signature,
    response: VerifiedMetadataResponse,
}

impl MetadataResponse {
    /// Creates and signs a new metadata response.
    pub fn new(signer: &Signer, response: &VerifiedMetadataResponse) -> Self {
        Self {
            signature: signer.sign(&standard_serialize(response)),
            response: response.clone(),
        }
    }

    /// Verifies the metadata response and returns the contained payload.
    pub fn verify(&self, verifying_pk: &PublicKey) -> Option<VerifiedMetadataResponse> {
        if self
            .signature
            .verify(verifying_pk, &standard_serialize(&self.response))
        {
            Some(self.response.clone())
        } else {
            None
        }
    }
}
