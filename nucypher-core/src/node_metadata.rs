use alloc::boxed::Box;
use alloc::string::String;

use serde::{Deserialize, Serialize};
use umbral_pre::{PublicKey, Signature, Signer};

use crate::address::Address;
use crate::fleet_state::FleetStateChecksum;
use crate::serde::{standard_serialize, ProtocolObject};

/// Node metadata.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadataPayload {
    /// The staker's Ethereum address.
    pub canonical_address: Address,
    /// The network identifier.
    pub domain: String,
    /// The timestamp of the metadata creation.
    pub timestamp_epoch: u32,
    /// The node's verifying key.
    pub verifying_key: PublicKey,
    /// The node's encrypting key.
    pub encrypting_key: PublicKey,
    /// The node's SSL certificate (serialized in PEM format).
    pub certificate_bytes: Box<[u8]>,
    /// The hostname of the node's REST service.
    pub host: String,
    /// The port of the node's REST service.
    pub port: u16,
    /// The node's verifying key signed by the private key corresponding to the worker address.
    pub decentralized_identity_evidence: Option<Box<[u8]>>, // TODO: make its own type?
}

/// Signed node metadata.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadata {
    signature: Signature,
    /// Authorized metadata payload.
    pub payload: NodeMetadataPayload,
}

impl ProtocolObject for NodeMetadata {}

impl NodeMetadata {
    /// Creates and signs a new metadata object.
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        // TODO: how can we ensure that `verifying_key` in `payload` is the same as in `signer`?
        Self {
            signature: signer.sign(&standard_serialize(&payload)),
            payload: payload.clone(),
        }
    }

    /// Verifies the consistency of signed node metadata.
    pub fn verify(&self) -> bool {
        // This method returns bool and not NodeMetadataPayload,
        // because NodeMetadata can be used before verification,
        // so we need access to its fields right away.

        // TODO: we could do this on deserialization, but it is a relatively expensive operation.

        // TODO: in order for this to make sense, `verifying_key` must be checked independently.
        // Currently it is done in `validate_worker()` (using `decentralized_identity_evidence`)
        // Can we validate the evidence here too?
        self.signature.verify(
            &self.payload.verifying_key,
            &standard_serialize(&self.payload),
        )
    }
}

/// A request for metadata exchange.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct MetadataRequest {
    /// The checksum of the requester's fleet state.
    pub fleet_state_checksum: FleetStateChecksum,
    /// A list of node metadata to announce.
    pub announce_nodes: Box<[NodeMetadata]>,
}

impl MetadataRequest {
    /// Creates a new request.
    pub fn new(fleet_state_checksum: &FleetStateChecksum, announce_nodes: &[NodeMetadata]) -> Self {
        Self {
            fleet_state_checksum: *fleet_state_checksum,
            announce_nodes: announce_nodes.to_vec().into_boxed_slice(),
        }
    }
}

impl ProtocolObject for MetadataRequest {}

/// Payload of the metadata response.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct VerifiedMetadataResponse {
    /// The timestamp of the most recent fleet state
    /// (the one consisting of the nodes that are being sent).
    pub timestamp_epoch: u32,
    /// A list of node metadata to announce.
    pub announce_nodes: Box<[NodeMetadata]>,
}

impl VerifiedMetadataResponse {
    /// Creates the new metadata response payload.
    pub fn new(timestamp_epoch: u32, announce_nodes: &[NodeMetadata]) -> Self {
        Self {
            timestamp_epoch,
            announce_nodes: announce_nodes.to_vec().into_boxed_slice(),
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
            signature: signer.sign(&standard_serialize(&response)),
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

impl ProtocolObject for MetadataResponse {}
