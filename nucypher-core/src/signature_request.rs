use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use umbral_pre::serde_bytes;

use crate::conditions::Context;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

/// Enum for different signature types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureRequestType {
    /// UserOperation signature request
    UserOp,
    /// Packed UserOperation signature request
    PackedUserOp,
    /// EIP-191 signature request
    #[serde(rename = "eip-191")]
    EIP191,
    /// EIP-712 signature request
    #[serde(rename = "eip-712")]
    EIP712,
}

impl fmt::Display for SignatureRequestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserOp => write!(f, "userop"),
            Self::PackedUserOp => write!(f, "packedUserOp"),
            Self::EIP191 => write!(f, "eip-191"),
            Self::EIP712 => write!(f, "eip-712"),
        }
    }
}

/// AA version enum for Account Abstraction versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AAVersion {
    /// Version 0.8.0
    #[serde(rename = "0.8.0")]
    V08,
    /// MDT version
    #[serde(rename = "mdt")]
    MDT,
}

impl fmt::Display for AAVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V08 => write!(f, "0.8.0"),
            Self::MDT => write!(f, "mdt"),
        }
    }
}

/// Base trait for signature requests
pub trait BaseSignatureRequest: Serialize + for<'de> Deserialize<'de> {
    /// Returns the cohort ID for this signature request
    fn cohort_id(&self) -> u32;
    /// Returns the chain ID for this signature request
    fn chain_id(&self) -> u32;
    /// Returns the signature type for this signature request
    fn signature_type(&self) -> SignatureRequestType;
    /// Returns the optional context for this signature request
    fn context(&self) -> Option<&Context>;
}

/// EIP-191 signature request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EIP191SignatureRequest {
    /// Data to be signed
    #[serde(with = "serde_bytes::as_base64")]
    pub data: Box<[u8]>,
    /// Cohort ID
    pub cohort_id: u32,
    /// Chain ID
    pub chain_id: u32,
    /// Optional context
    pub context: Option<Context>,
    /// Signature type (always EIP-191)
    pub signature_type: SignatureRequestType,
}

impl EIP191SignatureRequest {
    /// Creates a new EIP-191 signature request
    pub fn new(data: &[u8], cohort_id: u32, chain_id: u32, context: Option<Context>) -> Self {
        Self {
            data: data.to_vec().into_boxed_slice(),
            cohort_id,
            chain_id,
            context,
            signature_type: SignatureRequestType::EIP191,
        }
    }
}

impl BaseSignatureRequest for EIP191SignatureRequest {
    fn cohort_id(&self) -> u32 {
        self.cohort_id
    }

    fn chain_id(&self) -> u32 {
        self.chain_id
    }

    fn signature_type(&self) -> SignatureRequestType {
        self.signature_type
    }

    fn context(&self) -> Option<&Context> {
        self.context.as_ref()
    }
}

/// UserOperation for signature requests
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserOperation {
    /// The serialized user operation data
    pub data: String,
}

impl UserOperation {
    /// Creates a new UserOperation
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Serializes to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.as_bytes().to_vec()
    }

    /// Deserializes from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        String::from_utf8(bytes.to_vec())
            .map(|data| Self { data })
            .map_err(|e| e.to_string())
    }
}

/// UserOperation signature request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserOperationSignatureRequest {
    /// User operation to sign
    pub user_op: UserOperation,
    /// Cohort ID
    pub cohort_id: u32,
    /// Chain ID
    pub chain_id: u32,
    /// AA version
    pub aa_version: AAVersion,
    /// Optional context
    pub context: Option<Context>,
    /// Signature type (always UserOp)
    pub signature_type: SignatureRequestType,
}

impl UserOperationSignatureRequest {
    /// Creates a new UserOperation signature request
    pub fn new(
        user_op: UserOperation,
        cohort_id: u32,
        chain_id: u32,
        aa_version: AAVersion,
        context: Option<Context>,
    ) -> Self {
        Self {
            user_op,
            cohort_id,
            chain_id,
            aa_version,
            context,
            signature_type: SignatureRequestType::UserOp,
        }
    }
}

impl BaseSignatureRequest for UserOperationSignatureRequest {
    fn cohort_id(&self) -> u32 {
        self.cohort_id
    }

    fn chain_id(&self) -> u32 {
        self.chain_id
    }

    fn signature_type(&self) -> SignatureRequestType {
        self.signature_type
    }

    fn context(&self) -> Option<&Context> {
        self.context.as_ref()
    }
}

/// Packed UserOperation for signature requests
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedUserOperation {
    /// The serialized packed user operation data
    pub data: String,
}

impl PackedUserOperation {
    /// Creates a new PackedUserOperation
    pub fn new(data: String) -> Self {
        Self { data }
    }

    /// Serializes to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.data.as_bytes().to_vec()
    }

    /// Deserializes from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        String::from_utf8(bytes.to_vec())
            .map(|data| Self { data })
            .map_err(|e| e.to_string())
    }
}

/// Packed UserOperation signature request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackedUserOperationSignatureRequest {
    /// Packed user operation to sign
    pub packed_user_op: PackedUserOperation,
    /// Cohort ID
    pub cohort_id: u32,
    /// Chain ID
    pub chain_id: u32,
    /// AA version
    pub aa_version: AAVersion,
    /// Optional context
    pub context: Option<Context>,
    /// Signature type (always PackedUserOp)
    pub signature_type: SignatureRequestType,
}

impl PackedUserOperationSignatureRequest {
    /// Creates a new PackedUserOperation signature request
    pub fn new(
        packed_user_op: PackedUserOperation,
        cohort_id: u32,
        chain_id: u32,
        aa_version: AAVersion,
        context: Option<Context>,
    ) -> Self {
        Self {
            packed_user_op,
            cohort_id,
            chain_id,
            aa_version,
            context,
            signature_type: SignatureRequestType::PackedUserOp,
        }
    }
}

impl BaseSignatureRequest for PackedUserOperationSignatureRequest {
    fn cohort_id(&self) -> u32 {
        self.cohort_id
    }

    fn chain_id(&self) -> u32 {
        self.chain_id
    }

    fn signature_type(&self) -> SignatureRequestType {
        self.signature_type
    }

    fn context(&self) -> Option<&Context> {
        self.context.as_ref()
    }
}

/// Signature response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureResponse {
    /// Message hash
    #[serde(rename = "message_hash", with = "serde_bytes::as_base64")]
    pub hash: Box<[u8]>,
    /// Signature
    #[serde(with = "serde_bytes::as_base64")]
    pub signature: Box<[u8]>,
    /// Signature type
    pub signature_type: SignatureRequestType,
}

impl SignatureResponse {
    /// Creates a new signature response
    pub fn new(hash: &[u8], signature: &[u8], signature_type: SignatureRequestType) -> Self {
        Self {
            hash: hash.to_vec().into_boxed_slice(),
            signature: signature.to_vec().into_boxed_slice(),
            signature_type,
        }
    }
}

// ProtocolObject implementations

impl<'a> ProtocolObjectInner<'a> for EIP191SignatureRequest {
    fn brand() -> [u8; 4] {
        *b"E191"
    }

    fn version() -> (u16, u16) {
        (1, 0)
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

impl<'a> ProtocolObject<'a> for EIP191SignatureRequest {}

impl<'a> ProtocolObjectInner<'a> for UserOperationSignatureRequest {
    fn brand() -> [u8; 4] {
        *b"UOSR"
    }

    fn version() -> (u16, u16) {
        (1, 0)
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

impl<'a> ProtocolObject<'a> for UserOperationSignatureRequest {}

impl<'a> ProtocolObjectInner<'a> for PackedUserOperationSignatureRequest {
    fn brand() -> [u8; 4] {
        *b"PUOS"
    }

    fn version() -> (u16, u16) {
        (1, 0)
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

impl<'a> ProtocolObject<'a> for PackedUserOperationSignatureRequest {}

impl<'a> ProtocolObjectInner<'a> for SignatureResponse {
    fn brand() -> [u8; 4] {
        *b"SigR"
    }

    fn version() -> (u16, u16) {
        (1, 0)
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

impl<'a> ProtocolObject<'a> for SignatureResponse {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eip191_signature_request_serialization() {
        let data = b"test data";
        let request = EIP191SignatureRequest::new(data, 1, 137, None);
        
        let bytes = request.to_bytes();
        let deserialized = EIP191SignatureRequest::from_bytes(&bytes).unwrap();
        
        assert_eq!(request, deserialized);
        assert_eq!(deserialized.data.as_ref(), data);
        assert_eq!(deserialized.cohort_id, 1);
        assert_eq!(deserialized.chain_id, 137);
        assert_eq!(deserialized.signature_type, SignatureRequestType::EIP191);
    }

    #[test]
    fn test_user_operation_signature_request_serialization() {
        let user_op = UserOperation::new("test_user_op_data".to_string());
        let request = UserOperationSignatureRequest::new(
            user_op.clone(),
            1,
            137,
            AAVersion::V08,
            Some(Context::new("test_context")),
        );
        
        let bytes = request.to_bytes();
        let deserialized = UserOperationSignatureRequest::from_bytes(&bytes).unwrap();
        
        assert_eq!(request, deserialized);
        assert_eq!(deserialized.user_op.data, "test_user_op_data");
        assert_eq!(deserialized.aa_version, AAVersion::V08);
        assert_eq!(deserialized.context.as_ref().unwrap().as_ref(), "test_context");
    }

    #[test]
    fn test_signature_response_serialization() {
        let hash = b"test_hash";
        let signature = b"test_signature";
        let response = SignatureResponse::new(hash, signature, SignatureRequestType::UserOp);
        
        let bytes = response.to_bytes();
        let deserialized = SignatureResponse::from_bytes(&bytes).unwrap();
        
        assert_eq!(response, deserialized);
        assert_eq!(deserialized.hash.as_ref(), hash);
        assert_eq!(deserialized.signature.as_ref(), signature);
        assert_eq!(deserialized.signature_type, SignatureRequestType::UserOp);
    }

    #[test]
    fn test_aa_version_serialization() {
        // Test V08
        let user_op = UserOperation::new("test_v08".to_string());
        let request_v08 = UserOperationSignatureRequest::new(
            user_op,
            1,
            137,
            AAVersion::V08,
            None,
        );
        
        let bytes = request_v08.to_bytes();
        let deserialized_v08 = UserOperationSignatureRequest::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized_v08.aa_version, AAVersion::V08);
        
        // Test MDT
        let user_op_mdt = UserOperation::new("test_mdt".to_string());
        let request_mdt = UserOperationSignatureRequest::new(
            user_op_mdt,
            2,
            137,
            AAVersion::MDT,
            None,
        );
        
        let bytes_mdt = request_mdt.to_bytes();
        let deserialized_mdt = UserOperationSignatureRequest::from_bytes(&bytes_mdt).unwrap();
        assert_eq!(deserialized_mdt.aa_version, AAVersion::MDT);
        
        // Test Display trait
        assert_eq!(AAVersion::V08.to_string(), "0.8.0");
        assert_eq!(AAVersion::MDT.to_string(), "mdt");
    }
} 