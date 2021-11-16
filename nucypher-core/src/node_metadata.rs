use alloc::string::String;
use alloc::boxed::Box;

use umbral_pre::{PublicKey, Signer, Signature};
use serde::{Deserialize, Serialize};

use crate::treasure_map::ChecksumAddress;
use crate::serde::standard_serialize;

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadataPayload {
    public_address: ChecksumAddress,
    domain: String,
    timestamp_epoch: u32,
    verifying_key: PublicKey,
    encrypting_key: PublicKey,
    certificate_bytes: Box<[u8]>, // serialized SSL certificate in PEM format
    host: String,
    port: u16,
    decentralized_identity_evidence: Option<Box<[u8]>> // TODO: make its own type?
}

impl NodeMetadataPayload {

}

pub struct NodeMetadata {
    signature: Signature,
    payload: NodeMetadataPayload
}

impl NodeMetadata {
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        Self {
            signature: signer.sign(&standard_serialize(&payload)),
            payload: payload.clone()
        }
    }

    pub fn verify(self) -> Option<NodeMetadataPayload> {
        // Note: in order for this to make sense, `verifying_key` must be checked independently.
        // Currently it is done in `validate_worker()` (using `decentralized_identity_evidence`)
        // TODO: do this on deserialization?
        if self.signature.verify(&self.payload.verifying_key, &standard_serialize(&self.payload)) {
            return Some(self.payload)
        }
        else {
            return None
        }
    }
}
