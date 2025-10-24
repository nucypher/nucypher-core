use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};
use core::fmt;
use core::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use umbral_pre::serde_bytes;

use crate::address::Address;
use crate::conditions::Context;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

/// Enum for different signature types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SignatureRequestType {
    /// UserOperation signature request
    UserOp = 0,
    /// Packed UserOperation signature request
    PackedUserOp = 1,
}

impl SignatureRequestType {
    /// Convert to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Create from a u8
    pub fn from_u8(i: u8) -> Result<Self, String> {
        match i {
            0 => Ok(Self::UserOp),
            1 => Ok(Self::PackedUserOp),
            _ => Err(format!("Invalid signature request type: {}", i)),
        }
    }
}

impl fmt::Display for SignatureRequestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UserOp => write!(f, "userop"),
            Self::PackedUserOp => write!(f, "packedUserOp"),
        }
    }
}

/// AA v0.8.0 entryPoint address
pub const ENTRYPOINT_V08: &str = "0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108";
/// AA v0.7.0 entryPoint address
pub const ENTRYPOINT_V07: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

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

impl AAVersion {
    /// Return the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::V08 => "0.8.0",
            Self::MDT => "mdt",
        }
    }
}

impl FromStr for AAVersion {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "0.8.0" => Ok(Self::V08),
            "mdt" => Ok(Self::MDT),
            _ => Err(format!("Invalid AA version: {}", s)),
        }
    }
}

impl fmt::Display for AAVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V08 => write!(f, "{}", Self::V08.as_str()),
            Self::MDT => write!(f, "{}", Self::MDT.as_str()),
        }
    }
}

/// Base trait for signature requests
pub trait BaseSignatureRequest: Serialize + for<'de> Deserialize<'de> {
    /// Returns the cohort ID for this signature request
    fn cohort_id(&self) -> u32;
    /// Returns the chain ID for this signature request
    fn chain_id(&self) -> u64;
    /// Returns the signature type for this signature request
    fn signature_type(&self) -> SignatureRequestType;
    /// Returns the optional context for this signature request
    fn context(&self) -> Option<&Context>;
}

/// UserOperation for signature requests - https://eips.ethereum.org/EIPS/eip-4337
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserOperation {
    /// Address of the sender (smart contract account)
    pub sender: Address,
    /// Nonce for replay protection
    pub nonce: u64,
    /// The calldata to execute
    #[serde(with = "serde_bytes::as_base64")]
    pub call_data: Box<[u8]>,
    /// Gas limit for the call
    pub call_gas_limit: u128,
    /// Gas limit for verification
    pub verification_gas_limit: u128,
    /// Gas to cover overhead
    pub pre_verification_gas: u128,
    /// Maximum fee per gas unit
    pub max_fee_per_gas: u128,
    /// Maximum priority fee per gas unit
    pub max_priority_fee_per_gas: u128,
    /// Address of factory contract for account creation (empty for existing accounts)
    pub factory: Option<Address>,
    /// Data for factory contract account creation (empty for existing accounts)
    #[serde(with = "serde_bytes::as_base64")]
    pub factory_data: Box<[u8]>,
    /// Paymaster address (optional)
    pub paymaster: Option<Address>,
    /// Gas limit for paymaster verification
    pub paymaster_verification_gas_limit: u128,
    /// Gas limit for paymaster post-operation
    pub paymaster_post_op_gas_limit: u128,
    /// Paymaster-specific data
    #[serde(with = "serde_bytes::as_base64")]
    pub paymaster_data: Box<[u8]>,
}

impl UserOperation {
    /// Creates a new UserOperation
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender: Address,
        nonce: u64,
        call_data: &[u8],
        call_gas_limit: u128,
        verification_gas_limit: u128,
        pre_verification_gas: u128,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        factory: Option<Address>,
        factory_data: Option<&[u8]>,
        paymaster: Option<Address>,
        paymaster_verification_gas_limit: Option<u128>,
        paymaster_post_op_gas_limit: Option<u128>,
        paymaster_data: Option<&[u8]>,
    ) -> Self {
        Self {
            sender,
            nonce,
            call_data: call_data.to_vec().into_boxed_slice(),
            call_gas_limit,
            verification_gas_limit,
            pre_verification_gas,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            factory,
            factory_data: factory_data
                .map(|data| data.to_vec().into_boxed_slice())
                .unwrap_or_else(|| Box::new([])),
            paymaster,
            paymaster_verification_gas_limit: paymaster_verification_gas_limit.unwrap_or(0),
            paymaster_post_op_gas_limit: paymaster_post_op_gas_limit.unwrap_or(0),
            paymaster_data: paymaster_data
                .map(|data| data.to_vec().into_boxed_slice())
                .unwrap_or_else(|| Box::new([])),
        }
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
    pub chain_id: u64,
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
        chain_id: u64,
        aa_version: AAVersion,
        context: Option<&Context>,
    ) -> Self {
        Self {
            user_op,
            cohort_id,
            chain_id,
            aa_version,
            context: context.cloned(),
            signature_type: SignatureRequestType::UserOp,
        }
    }
}

impl BaseSignatureRequest for UserOperationSignatureRequest {
    fn cohort_id(&self) -> u32 {
        self.cohort_id
    }

    fn chain_id(&self) -> u64 {
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
    /// Address of the sender (smart contract account)
    pub sender: Address,
    /// Nonce for replay protection
    pub nonce: u64,
    /// Factory and data for account creation
    #[serde(with = "serde_bytes::as_base64")]
    pub init_code: Box<[u8]>,
    /// The calldata to execute
    #[serde(with = "serde_bytes::as_base64")]
    pub call_data: Box<[u8]>,
    /// Packed gas limits (verification gas limit << 128 | call gas limit)
    #[serde(with = "serde_bytes::as_base64")]
    pub account_gas_limits: Box<[u8]>,
    /// Gas to cover overhead
    pub pre_verification_gas: u128,
    /// Packed gas fees (max priority fee << 128 | max fee)
    #[serde(with = "serde_bytes::as_base64")]
    pub gas_fees: Box<[u8]>,
    /// Packed paymaster data (address, verification gas limit, post-op gas limit, data)
    #[serde(with = "serde_bytes::as_base64")]
    pub paymaster_and_data: Box<[u8]>,
}

impl PackedUserOperation {
    /// Creates a new PackedUserOperation
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender: Address,
        nonce: u64,
        init_code: &[u8],
        call_data: &[u8],
        account_gas_limits: &[u8],
        pre_verification_gas: u128,
        gas_fees: &[u8],
        paymaster_and_data: &[u8],
    ) -> Self {
        Self {
            sender,
            nonce,
            init_code: init_code.to_vec().into_boxed_slice(),
            call_data: call_data.to_vec().into_boxed_slice(),
            account_gas_limits: account_gas_limits.to_vec().into_boxed_slice(),
            pre_verification_gas,
            gas_fees: gas_fees.to_vec().into_boxed_slice(),
            paymaster_and_data: paymaster_and_data.to_vec().into_boxed_slice(),
        }
    }

    /// Packs account gas limits into a 32-byte value (u128 verification_gas_limit << 128 | u128 call_gas_limit)
    fn pack_account_gas_limits(call_gas_limit: u128, verification_gas_limit: u128) -> [u8; 32] {
        let mut result = [0u8; 32];
        // Pack as: verification_gas_limit << 128 | call_gas_limit
        // Each value is u128, so verification goes in upper 16 bytes, call in lower 16 bytes
        result[0..16].copy_from_slice(&verification_gas_limit.to_be_bytes());
        result[16..32].copy_from_slice(&call_gas_limit.to_be_bytes());
        result
    }

    /// Packs gas fees into a 32-byte value (u128 max_priority_fee_per_gas << 128 | u128 max_fee_per_gas)
    fn pack_gas_fees(max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> [u8; 32] {
        let mut result = [0u8; 32];
        // Pack as: max_priority_fee_per_gas << 128 | max_fee_per_gas
        // Each value is u128, so priority goes in upper 16 bytes, max_fee in lower 16 bytes
        result[0..16].copy_from_slice(&max_priority_fee_per_gas.to_be_bytes());
        result[16..32].copy_from_slice(&max_fee_per_gas.to_be_bytes());
        result
    }

    /// Packs paymaster data with u128 gas limits
    fn pack_paymaster_and_data(
        paymaster: Option<&Address>,
        paymaster_verification_gas_limit: u128,
        paymaster_post_op_gas_limit: u128,
        paymaster_data: &[u8],
    ) -> Vec<u8> {
        match paymaster {
            None => Vec::new(),
            Some(addr) => {
                let mut result = Vec::with_capacity(20 + 16 + 16 + paymaster_data.len());
                result.extend_from_slice(addr.as_ref());

                // Verification gas limit as 16 bytes big-endian (full u128)
                result.extend_from_slice(&paymaster_verification_gas_limit.to_be_bytes());

                // Post-op gas limit as 16 bytes big-endian (full u128)
                result.extend_from_slice(&paymaster_post_op_gas_limit.to_be_bytes());

                result.extend_from_slice(paymaster_data);
                result
            }
        }
    }

    fn pack_init_code(factory: Option<&Address>, factory_data: &[u8]) -> Vec<u8> {
        match factory {
            None => Vec::new(),
            Some(addr) => {
                let mut result = Vec::with_capacity(20 + factory_data.len());
                result.extend_from_slice(addr.as_ref());
                result.extend_from_slice(factory_data);
                result
            }
        }
    }

    /// Creates a PackedUserOperation from a UserOperation
    pub fn from_user_operation(user_op: &UserOperation) -> Self {
        let account_gas_limits =
            Self::pack_account_gas_limits(user_op.call_gas_limit, user_op.verification_gas_limit);

        let gas_fees =
            Self::pack_gas_fees(user_op.max_fee_per_gas, user_op.max_priority_fee_per_gas);

        let paymaster_and_data = Self::pack_paymaster_and_data(
            user_op.paymaster.as_ref(),
            user_op.paymaster_verification_gas_limit,
            user_op.paymaster_post_op_gas_limit,
            &user_op.paymaster_data,
        );

        let init_code = Self::pack_init_code(user_op.factory.as_ref(), &user_op.factory_data);

        Self {
            sender: user_op.sender,
            nonce: user_op.nonce,
            init_code: init_code.to_vec().into_boxed_slice(),
            call_data: user_op.call_data.clone(),
            account_gas_limits: account_gas_limits.to_vec().into_boxed_slice(),
            pre_verification_gas: user_op.pre_verification_gas,
            gas_fees: gas_fees.to_vec().into_boxed_slice(),
            paymaster_and_data: paymaster_and_data.into_boxed_slice(),
        }
    }

    /// Converts to EIP-712 message format
    pub fn to_eip712_message(&self, aa_version: &AAVersion) -> serde_json::Map<String, JsonValue> {
        let mut message = serde_json::Map::new();
        message.insert(
            "sender".into(),
            JsonValue::String(format!("0x{}", hex::encode(self.sender.as_ref()))),
        );
        message.insert("nonce".into(), JsonValue::Number(self.nonce.into()));
        message.insert(
            "initCode".into(),
            JsonValue::String(format!("0x{}", hex::encode(&self.init_code))),
        );
        message.insert(
            "callData".into(),
            JsonValue::String(format!("0x{}", hex::encode(&self.call_data))),
        );
        message.insert(
            "accountGasLimits".into(),
            JsonValue::String(format!("0x{}", hex::encode(&self.account_gas_limits))),
        );
        message.insert(
            "preVerificationGas".into(),
            JsonValue::String(self.pre_verification_gas.to_string()),
        );
        message.insert(
            "gasFees".into(),
            JsonValue::String(format!("0x{}", hex::encode(&self.gas_fees))),
        );
        message.insert(
            "paymasterAndData".into(),
            JsonValue::String(format!("0x{}", hex::encode(&self.paymaster_and_data))),
        );

        if *aa_version == AAVersion::MDT {
            message.insert(
                "entryPoint".into(),
                JsonValue::String(ENTRYPOINT_V07.into()),
            );
        }

        message
    }

    /// Gets the EIP-712 domain
    pub fn get_domain(
        &self,
        aa_version: &AAVersion,
        chain_id: u64,
    ) -> serde_json::Map<String, JsonValue> {
        let mut domain = serde_json::Map::new();

        let name = if *aa_version != AAVersion::MDT {
            "ERC4337"
        } else {
            "MultiSigDeleGator"
        };
        domain.insert("name".into(), JsonValue::String(name.into()));
        domain.insert("version".into(), JsonValue::String("1".into()));
        domain.insert("chainId".into(), JsonValue::Number(chain_id.into()));

        let verifying_contract = if *aa_version != AAVersion::MDT {
            ENTRYPOINT_V08.into()
        } else {
            format!("0x{}", hex::encode(self.sender.as_ref()))
        };
        domain.insert(
            "verifyingContract".into(),
            JsonValue::String(verifying_contract),
        );

        domain
    }

    /// Converts to EIP-712 struct format
    pub fn to_eip712_struct(
        &self,
        aa_version: &AAVersion,
        chain_id: u64,
    ) -> serde_json::Map<String, JsonValue> {
        let mut result = serde_json::Map::new();

        // Create types
        let mut types = serde_json::Map::new();

        // EIP712Domain type
        let mut domain_type = Vec::new();
        let mut name_field = serde_json::Map::new();
        name_field.insert("name".into(), JsonValue::String("name".into()));
        name_field.insert("type".into(), JsonValue::String("string".into()));
        domain_type.push(JsonValue::Object(name_field));

        let mut version_field = serde_json::Map::new();
        version_field.insert("name".into(), JsonValue::String("version".into()));
        version_field.insert("type".into(), JsonValue::String("string".into()));
        domain_type.push(JsonValue::Object(version_field));

        let mut chain_id_field = serde_json::Map::new();
        chain_id_field.insert("name".into(), JsonValue::String("chainId".into()));
        chain_id_field.insert("type".into(), JsonValue::String("uint256".into()));
        domain_type.push(JsonValue::Object(chain_id_field));

        let mut verifying_contract_field = serde_json::Map::new();
        verifying_contract_field
            .insert("name".into(), JsonValue::String("verifyingContract".into()));
        verifying_contract_field.insert("type".into(), JsonValue::String("address".into()));
        domain_type.push(JsonValue::Object(verifying_contract_field));

        types.insert("EIP712Domain".into(), JsonValue::Array(domain_type));

        // PackedUserOperation type
        let mut packed_user_op_type = Vec::new();

        let field_specs = vec![
            ("sender", "address"),
            ("nonce", "uint256"),
            ("initCode", "bytes"),
            ("callData", "bytes"),
            ("accountGasLimits", "bytes32"),
            ("preVerificationGas", "uint256"),
            ("gasFees", "bytes32"),
            ("paymasterAndData", "bytes"),
        ];

        for (name, type_str) in field_specs {
            let mut field = serde_json::Map::new();
            field.insert("name".into(), JsonValue::String(name.into()));
            field.insert("type".into(), JsonValue::String(type_str.into()));
            packed_user_op_type.push(JsonValue::Object(field));
        }

        if *aa_version == AAVersion::MDT {
            let mut entry_point_field = serde_json::Map::new();
            entry_point_field.insert("name".into(), JsonValue::String("entryPoint".into()));
            entry_point_field.insert("type".into(), JsonValue::String("address".into()));
            packed_user_op_type.push(JsonValue::Object(entry_point_field));
        }

        types.insert(
            "PackedUserOperation".into(),
            JsonValue::Array(packed_user_op_type),
        );

        // Build final result
        result.insert("types".into(), JsonValue::Object(types));
        result.insert(
            "primaryType".into(),
            JsonValue::String("PackedUserOperation".into()),
        );
        result.insert(
            "domain".into(),
            JsonValue::Object(self.get_domain(aa_version, chain_id)),
        );
        result.insert(
            "message".into(),
            JsonValue::Object(self.to_eip712_message(aa_version)),
        );

        result
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
    pub chain_id: u64,
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
        chain_id: u64,
        aa_version: AAVersion,
        context: Option<&Context>,
    ) -> Self {
        Self {
            packed_user_op,
            cohort_id,
            chain_id,
            aa_version,
            context: context.cloned(),
            signature_type: SignatureRequestType::PackedUserOp,
        }
    }
}

impl BaseSignatureRequest for PackedUserOperationSignatureRequest {
    fn cohort_id(&self) -> u32 {
        self.cohort_id
    }

    fn chain_id(&self) -> u64 {
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

impl<'a> ProtocolObjectInner<'a> for UserOperation {
    fn brand() -> [u8; 4] {
        *b"UOPR"
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

impl<'a> ProtocolObject<'a> for UserOperation {}

impl<'a> ProtocolObjectInner<'a> for PackedUserOperation {
    fn brand() -> [u8; 4] {
        *b"PUOP"
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

impl<'a> ProtocolObject<'a> for PackedUserOperation {}

/// Enum to hold any type of signature request for direct returns
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectSignatureRequest {
    /// UserOperation signature request
    UserOp(UserOperationSignatureRequest),
    /// PackedUserOperation signature request
    PackedUserOp(PackedUserOperationSignatureRequest),
}

impl DirectSignatureRequest {
    /// Deserialize any signature request from bytes by checking the brand identifier
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() < 4 {
            return Err("Insufficient bytes for brand identifier".into());
        }

        // Extract the 4-byte brand identifier
        let brand = [bytes[0], bytes[1], bytes[2], bytes[3]];

        match &brand {
            b"UOSR" => UserOperationSignatureRequest::from_bytes(bytes)
                .map(Self::UserOp)
                .map_err(|e| format!("Failed to deserialize UserOperationSignatureRequest: {}", e)),
            b"PUOS" => PackedUserOperationSignatureRequest::from_bytes(bytes)
                .map(Self::PackedUserOp)
                .map_err(|e| {
                    format!(
                        "Failed to deserialize PackedUserOperationSignatureRequest: {}",
                        e
                    )
                }),
            _ => Err(format!("Unknown signature request brand: {:?}", brand)),
        }
    }

    /// Get the signature type for this request
    pub fn signature_type(&self) -> SignatureRequestType {
        match self {
            Self::UserOp(_) => SignatureRequestType::UserOp,
            Self::PackedUserOp(_) => SignatureRequestType::PackedUserOp,
        }
    }

    /// Get the cohort ID for this request
    pub fn cohort_id(&self) -> u32 {
        match self {
            Self::UserOp(req) => req.cohort_id(),
            Self::PackedUserOp(req) => req.cohort_id(),
        }
    }

    /// Get the chain ID for this request  
    pub fn chain_id(&self) -> u64 {
        match self {
            Self::UserOp(req) => req.chain_id(),
            Self::PackedUserOp(req) => req.chain_id(),
        }
    }

    /// Get the optional context for this request
    pub fn context(&self) -> Option<&Context> {
        match self {
            Self::UserOp(req) => req.context(),
            Self::PackedUserOp(req) => req.context(),
        }
    }
}

/// Utility function to deserialize any signature request from bytes
pub fn deserialize_signature_request(bytes: &[u8]) -> Result<DirectSignatureRequest, String> {
    DirectSignatureRequest::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_user_operation_signature_request_serialization() {
        let sender = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let paymaster =
            Some(Address::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap());
        let factory =
            Some(Address::from_str("0x12345678901234567890abcdefabcdefabcdefab").unwrap());

        let user_op = UserOperation::new(
            sender,
            42,
            b"call_data",
            100000,
            200000,
            50000,
            20_000_000_000, // 20 gwei
            1_000_000_000,  // 1 gwei
            factory,
            Some(b"factory_data"),
            paymaster,
            Some(300000),
            Some(100000),
            Some(b"paymaster_data"),
        );
        let request = UserOperationSignatureRequest::new(
            user_op.clone(),
            1,
            137,
            AAVersion::V08,
            Some(&Context::new("test_context")),
        );

        let bytes = request.to_bytes();
        let deserialized = UserOperationSignatureRequest::from_bytes(&bytes).unwrap();

        assert_eq!(request, deserialized);
        assert_eq!(deserialized.user_op.sender, sender);
        assert_eq!(deserialized.user_op.nonce, 42);
        assert_eq!(deserialized.aa_version, AAVersion::V08);
        assert_eq!(
            deserialized.context.as_ref().unwrap().as_ref(),
            "test_context"
        );
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
        let sender = Address::from_str("0x789abcdef0123456789abcdef0123456789abcde").unwrap();
        let user_op = UserOperation::new(
            sender,
            1,
            b"",
            0,
            0,
            0,
            0,
            0,
            None,
            Some(b""),
            None,
            Some(0),
            Some(0),
            Some(b""),
        );
        let request_v08 = UserOperationSignatureRequest::new(
            user_op.clone(),
            1,
            137,
            AAVersion::V08,
            Some(&Context::new("test_context")),
        );

        let bytes = request_v08.to_bytes();
        let deserialized_v08 = UserOperationSignatureRequest::from_bytes(&bytes).unwrap();
        assert_eq!(deserialized_v08.aa_version, AAVersion::V08);

        // Test MDT
        let sender_mdt = Address::from_str("0xabcdef0123456789abcdef0123456789abcdef01").unwrap();
        let user_op_mdt = UserOperation::new(
            sender_mdt,
            2,
            b"call_data_mdt",
            0,
            0,
            0,
            0,
            0,
            // Optional fields
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let request_mdt = UserOperationSignatureRequest::new(
            user_op_mdt,
            2,
            137,
            AAVersion::MDT,
            Some(&Context::new("test_context")),
        );

        let bytes_mdt = request_mdt.to_bytes();
        let deserialized_mdt = UserOperationSignatureRequest::from_bytes(&bytes_mdt).unwrap();
        assert_eq!(deserialized_mdt.aa_version, AAVersion::MDT);

        // Test Display trait
        assert_eq!(AAVersion::V08.to_string(), "0.8.0");
        assert_eq!(AAVersion::MDT.to_string(), "mdt");
    }

    #[test]
    fn test_packed_user_operation_conversion() {
        let sender = Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let paymaster =
            Some(Address::from_str("0xabcdefabcdefabcdefabcdefabcdefabcdefabcd").unwrap());
        let factory =
            Some(Address::from_str("0x12345678901234567890abcdefabcdefabcdefab").unwrap());

        let user_op = UserOperation::new(
            sender,
            100,
            b"execution_data",
            150000,
            250000,
            60000,
            30_000_000_000,
            2_000_000_000,
            factory,
            Some(b"factory_data"),
            paymaster,
            Some(400000),
            Some(200000),
            Some(b"paymaster_specific_data"),
        );

        let packed = PackedUserOperation::from_user_operation(&user_op);

        assert_eq!(packed.sender, user_op.sender);
        assert_eq!(packed.nonce, user_op.nonce);
        assert_eq!(packed.init_code.len(), 32);
        assert_eq!(packed.call_data, user_op.call_data);
        assert_eq!(packed.pre_verification_gas, user_op.pre_verification_gas);

        // Check account gas limits packing
        assert_eq!(packed.account_gas_limits.len(), 32);

        // Check gas fees packing
        assert_eq!(packed.gas_fees.len(), 32);

        // Check paymaster data packing (20 bytes address + 16 bytes + 16 bytes + data)
        assert_eq!(
            packed.paymaster_and_data.len(),
            20 + 16 + 16 + b"paymaster_specific_data".len()
        );
    }
}
