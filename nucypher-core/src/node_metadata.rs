use alloc::boxed::Box;
use alloc::string::String;

use generic_array::GenericArray;
use serde::{Deserialize, Serialize};
use typenum::U32;
use umbral_pre::{PublicKey, Signature, Signer};
use ethereum_types::Address;

use crate::fleet_state::FleetStateChecksum;
use crate::serde::{
    serde_deserialize_bytes_as_hex, serde_serialize_bytes_as_hex, standard_serialize,
};

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadataPayload {
    pub(crate) public_address: Address,
    domain: String,
    timestamp_epoch: u32,
    verifying_key: PublicKey,
    encrypting_key: PublicKey,
    certificate_bytes: Box<[u8]>, // serialized SSL certificate in PEM format
    host: String,
    port: u16,
    decentralized_identity_evidence: Option<Box<[u8]>>, // TODO: make its own type?
}

impl NodeMetadataPayload {}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadata {
    signature: Signature,
    pub(crate) payload: NodeMetadataPayload,
}

impl NodeMetadata {
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        Self {
            signature: signer.sign(&standard_serialize(&payload)),
            payload: payload.clone(),
        }
    }

    pub fn verify(self) -> Option<NodeMetadataPayload> {
        // Note: in order for this to make sense, `verifying_key` must be checked independently.
        // Currently it is done in `validate_worker()` (using `decentralized_identity_evidence`)
        // TODO: do this on deserialization?
        if self.signature.verify(
            &self.payload.verifying_key,
            &standard_serialize(&self.payload),
        ) {
            return Some(self.payload);
        } else {
            return None;
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct MetadataRequest {
    fleet_state_checksum: FleetStateChecksum,
    announce_nodes: Option<Box<[NodeMetadata]>>,
}

impl MetadataRequest {
    pub fn new(
        fleet_state_checksum: FleetStateChecksum,
        announce_nodes: Option<Box<[NodeMetadata]>>,
    ) -> Self {
        Self {
            fleet_state_checksum,
            announce_nodes,
        }
    }
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct VerifiedMetadataResponse {
    timestamp_epoch: u32,
    this_node: Option<NodeMetadata>,
    other_nodes: Option<Box<NodeMetadata>>,
}

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct MetadataResponse {
    signature: Signature,
    response: VerifiedMetadataResponse,
}

impl MetadataResponse {
    pub fn new(signer: &Signer, response: &VerifiedMetadataResponse) -> Self {
        Self {
            signature: signer.sign(&standard_serialize(response)),
            response: response.clone(),
        }
    }

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
