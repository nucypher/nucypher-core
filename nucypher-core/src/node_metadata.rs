use alloc::boxed::Box;
use alloc::string::String;
use alloc::string::ToString;
use core::fmt;

use ferveo::api::ValidatorPublicKey as FerveoPublicKey;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use sha3::{digest::Update, Digest, Keccak256};
use umbral_pre::{serde_bytes, PublicKey, RecoverableSignature, Signature, Signer};

use crate::address::Address;
use crate::fleet_state::FleetStateChecksum;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};
use crate::VerificationError;

/// Indicates an error during canonical address derivation from a signature.
pub enum AddressDerivationError {
    /// Signature is missing from the payload.
    NoSignatureInPayload,
    /// Failed to recover the public key from the signature.
    RecoveryFailed(String),
}

impl fmt::Display for AddressDerivationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoSignatureInPayload => write!(f, "Signature is missing from the payload"),
            Self::RecoveryFailed(err) => write!(
                f,
                "Failed to recover the public key from the signature: {}",
                err
            ),
        }
    }
}

/// Mimics the format of `eth_account.messages.encode_defunct()` which NuCypher codebase uses.
fn encode_defunct(message: &[u8]) -> Keccak256 {
    Keccak256::new()
        .chain(b"\x19")
        .chain(b"E") // version
        .chain(b"thereum Signed Message:\n") // header
        .chain(message.len().to_string().as_bytes())
        .chain(message)
}

/// Node metadata.
#[serde_as]
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadataPayload {
    /// The staking provider's Ethereum address.
    pub staking_provider_address: Address,
    /// The network identifier.
    pub domain: String,
    /// The timestamp of the metadata creation.
    pub timestamp_epoch: u32,
    /// The node's verifying key.
    pub verifying_key: PublicKey,
    /// The node's encrypting key.
    pub encrypting_key: PublicKey,
    /// Ferveo public key to use for DKG participation.
    pub ferveo_public_key: FerveoPublicKey,
    /// The node's SSL certificate (serialized in DER format).
    #[serde(with = "serde_bytes::as_base64")]
    pub certificate_der: Box<[u8]>,
    /// The hostname of the node's REST service.
    pub host: String,
    /// The port of the node's REST service.
    pub port: u16,
    /// The node's verifying key signed by the private key corresponding to the operator address.
    pub operator_signature: RecoverableSignature,
}

impl NodeMetadataPayload {
    // Standard payload serialization for signing purposes.
    fn to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(self)
    }

    /// Derives the address corresponding to the public key that was used
    /// to create `operator_signature`.
    pub fn derive_operator_address(&self) -> Result<Address, AddressDerivationError> {
        let digest = encode_defunct(&self.verifying_key.to_compressed_bytes());
        let key = PublicKey::recover_from_prehash(&digest.finalize(), &self.operator_signature)
            .map_err(AddressDerivationError::RecoveryFailed)?;
        Ok(Address::from_public_key(&key))
    }
}

/// Signed node metadata.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct NodeMetadata {
    signature: Signature,
    /// Authorized metadata payload.
    pub payload: NodeMetadataPayload,
}

impl NodeMetadata {
    /// Creates and signs a new metadata object.
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        // TODO: how can we ensure that `verifying_key` in `payload` is the same as in `signer`?
        Self {
            signature: signer.sign(&payload.to_bytes()),
            payload: payload.clone(),
        }
    }

    /// Verifies the consistency of signed node metadata.
    pub fn verify(&self) -> bool {
        // This method returns bool and not NodeMetadataPayload,
        // because NodeMetadata can be used before verification,
        // so we need access to its fields right away.
        // This may change depending on the decision in
        // https://github.com/nucypher/nucypher/issues/2876

        // We could do this on deserialization, but it is a relatively expensive operation.
        self.signature
            .verify(&self.payload.verifying_key, &self.payload.to_bytes())
    }
}

impl<'a> ProtocolObjectInner<'a> for NodeMetadata {
    fn brand() -> [u8; 4] {
        *b"NdMd"
    }

    fn version() -> (u16, u16) {
        // Note: if `NodeMetadataPayload` has a field added, it will have be a major version change,
        // since the whole payload is signed (so we can't just substitute the default).
        // Alternatively, one can add new fields to `NodeMetadata` itself
        // (but then they won't be signed).
        (4, 0)
    }

    fn unversioned_to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(&self)
    }

    fn unversioned_from_bytes(minor_version: u16, bytes: &[u8]) -> Option<Result<Self, String>> {
        if minor_version == 0 {
            Some(messagepack_deserialize(bytes))
        } else {
            None
        }
    }
}

impl<'a> ProtocolObject<'a> for NodeMetadata {}

/// A request for metadata exchange.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
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

impl<'a> ProtocolObjectInner<'a> for MetadataRequest {
    fn brand() -> [u8; 4] {
        *b"MdRq"
    }

    fn version() -> (u16, u16) {
        (3, 0)
    }

    fn unversioned_to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(&self)
    }

    fn unversioned_from_bytes(minor_version: u16, bytes: &[u8]) -> Option<Result<Self, String>> {
        if minor_version == 0 {
            Some(messagepack_deserialize(bytes))
        } else {
            None
        }
    }
}

impl<'a> ProtocolObject<'a> for MetadataRequest {}

/// Payload of the metadata response.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct MetadataResponsePayload {
    /// The timestamp of the most recent fleet state
    /// (the one consisting of the nodes that are being sent).
    pub timestamp_epoch: u32,
    /// A list of node metadata to announce.
    pub announce_nodes: Box<[NodeMetadata]>,
}

impl MetadataResponsePayload {
    /// Creates the new metadata response payload.
    pub fn new(timestamp_epoch: u32, announce_nodes: &[NodeMetadata]) -> Self {
        Self {
            timestamp_epoch,
            announce_nodes: announce_nodes.to_vec().into_boxed_slice(),
        }
    }

    // Standard payload serialization for signing purposes.
    fn to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(self)
    }
}

/// A response returned by an Ursula containing known node metadata.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct MetadataResponse {
    signature: Signature,
    payload: MetadataResponsePayload,
}

impl MetadataResponse {
    /// Creates and signs a new metadata response.
    pub fn new(signer: &Signer, payload: &MetadataResponsePayload) -> Self {
        Self {
            signature: signer.sign(&payload.to_bytes()),
            payload: payload.clone(),
        }
    }

    /// Verifies the metadata response and returns the contained payload.
    pub fn verify(
        self,
        verifying_pk: &PublicKey,
    ) -> Result<MetadataResponsePayload, VerificationError> {
        if self
            .signature
            .verify(verifying_pk, &self.payload.to_bytes())
        {
            Ok(self.payload)
        } else {
            Err(VerificationError)
        }
    }
}

impl<'a> ProtocolObjectInner<'a> for MetadataResponse {
    fn brand() -> [u8; 4] {
        *b"MdRs"
    }

    fn version() -> (u16, u16) {
        // Note: if `MetadataResponsePayload` has a field added,
        // it will have be a major version change,
        // since the whole payload is signed (so we can't just substitute the default).
        // Alternatively, one can add new fields to `NodeMetadata` itself
        // (but then they won't be signed).
        (3, 0)
    }

    fn unversioned_to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(&self)
    }

    fn unversioned_from_bytes(minor_version: u16, bytes: &[u8]) -> Option<Result<Self, String>> {
        if minor_version == 0 {
            Some(messagepack_deserialize(bytes))
        } else {
            None
        }
    }
}

impl<'a> ProtocolObject<'a> for MetadataResponse {}
