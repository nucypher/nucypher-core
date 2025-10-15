from typing import Dict, List, Mapping, Optional, Sequence, Set, Tuple, Union, final, Any

from .ferveo import (
    Ciphertext,
    CiphertextHeader,
    DkgPublicKey,
    FerveoPublicKey,
    FerveoVariant,
    SharedSecret,
)
from .umbral import (
    Capsule,
    PublicKey,
    RecoverableSignature,
    SecretKey,
    Signer,
    VerifiedCapsuleFrag,
    VerifiedKeyFrag,
)

@final
class Address:

    def __init__(self, address_bytes: bytes):
        ...

    def __bytes__(self) -> bytes:
        ...

    def __hash__(self) -> int:
        ...

    def __eq__(self, other) -> bool:
        ...


@final
class Conditions:

    def __init__(self, conditions: str):
        ...

    @staticmethod
    def from_string(conditions: str) -> Conditions:
        ...

    def __str__(self) -> str:
        ...


@final
class Context:

    def __init__(self, context: str):
        ...

    def __str__(self) -> str:
        ...


@final
class MessageKit:

    @staticmethod
    def from_bytes(data: bytes) -> MessageKit:
        ...

    def __init__(
            self,
            policy_encrypting_key: PublicKey,
            plaintext: bytes,
            conditions: Optional[Conditions]
    ):
        ...

    def decrypt(self, sk: SecretKey) -> bytes:
        ...

    def decrypt_reencrypted(
            self,
            sk: SecretKey,
            policy_encrypting_key: PublicKey,
            vcfrags: Sequence[VerifiedCapsuleFrag]
    ) -> bytes:
        ...

    def __bytes__(self) -> bytes:
        ...

    capsule: Capsule

    conditions: Optional[Conditions]


@final
class HRAC:

    def __init__(
            self,
            publisher_verifying_key: PublicKey,
            bob_verifying_key: PublicKey,
            label: bytes,
    ):
        ...

    @staticmethod
    def from_bytes(data: bytes) -> HRAC:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class EncryptedKeyFrag:

    def __init__(
            self,
            signer: Signer,
            recipient_key: PublicKey,
            hrac: HRAC,
            verified_kfrag: VerifiedKeyFrag,
    ):
        ...

    def decrypt(
            self,
            sk: SecretKey,
            hrac: HRAC,
            publisher_verifying_key: PublicKey,
    ) -> VerifiedKeyFrag:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> EncryptedKeyFrag:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class TreasureMap:

    def __init__(
            self,
            signer: Signer,
            hrac: HRAC,
            policy_encrypting_key: PublicKey,
            assigned_kfrags: Mapping[Address, Tuple[PublicKey, VerifiedKeyFrag]],
            threshold: int,
    ):
        ...

    def encrypt(self, signer: Signer, recipient_key: PublicKey) -> EncryptedTreasureMap:
        ...

    def make_revocation_orders(self, signer: Signer) -> List[RevocationOrder]:
        ...

    destinations: Dict[Address, EncryptedKeyFrag]

    hrac: HRAC

    threshold: int

    policy_encrypting_key: PublicKey

    publisher_verifying_key: PublicKey

    @staticmethod
    def from_bytes(data: bytes) -> TreasureMap:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class EncryptedTreasureMap:

    def decrypt(
            self,
            sk: SecretKey,
            publisher_verifying_key: PublicKey,
    ) -> TreasureMap:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> EncryptedTreasureMap:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class ReencryptionRequest:

    def __init__(
            self,
            capsules: Sequence[Capsule],
            hrac: HRAC,
            encrypted_kfrag: EncryptedKeyFrag,
            publisher_verifying_key: PublicKey,
            bob_verifying_key: PublicKey,
            conditions: Optional[Conditions],
            context: Optional[Context],
    ):
        ...

    hrac: HRAC

    publisher_verifying_key: PublicKey

    bob_verifying_key: PublicKey

    encrypted_kfrag: EncryptedKeyFrag

    capsules: List[Capsule]

    conditions: Optional[Conditions]

    context: Optional[Context]

    @staticmethod
    def from_bytes(data: bytes) -> ReencryptionRequest:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class ReencryptionResponse:

    def __init__(
            self,
            signer: Signer,
            capsules_and_vcfrags:
            Sequence[Tuple[Capsule, VerifiedCapsuleFrag]]
    ):
        ...

    def verify(
            self,
            capsules: Sequence[Capsule],
            alice_verifying_key: PublicKey,
            ursula_verifying_key: PublicKey,
            policy_encrypting_key: PublicKey,
            bob_encrypting_key: PublicKey,
    ) -> List[VerifiedCapsuleFrag]:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> ReencryptionResponse:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class RetrievalKit:

    @staticmethod
    def from_message_kit(message_kit: MessageKit) -> RetrievalKit:
        ...

    def __init__(
            self,
            capsule: Capsule,
            queried_addresses: Set[Address],
            conditions: Optional[Conditions],
    ):
        ...

    capsule: Capsule

    queried_addresses: Set[Address]

    conditions: Optional[Conditions]

    @staticmethod
    def from_bytes(data: bytes) -> RetrievalKit:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class RevocationOrder:

    def __init__(
            self,
            signer: Signer,
            staking_provider_address: Address,
            encrypted_kfrag: EncryptedKeyFrag,
    ):
        ...

    def verify(
            self,
            alice_verifying_key: PublicKey,
    ) -> Tuple[Address, EncryptedKeyFrag]:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> RevocationOrder:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class NodeMetadataPayload:

    def __init__(
            self,
            staking_provider_address: Address,
            domain: str,
            timestamp_epoch: int,
            verifying_key: PublicKey,
            encrypting_key: PublicKey,
            ferveo_public_key: FerveoPublicKey,
            certificate_der: bytes,
            host: str,
            port: int,
            operator_signature: RecoverableSignature,
    ):
        ...

    staking_provider_address: Address

    verifying_key: PublicKey

    encrypting_key: PublicKey

    ferveo_public_key: FerveoPublicKey

    operator_signature: RecoverableSignature

    domain: str

    host: str

    port: int

    timestamp_epoch: int

    certificate_der: bytes

    def derive_operator_address(self) -> Address:
        ...


@final
class NodeMetadata:

    def __init__(self, signer: Signer, payload: NodeMetadataPayload):
        ...

    def verify(self) -> bool:
        ...

    payload: NodeMetadataPayload

    @staticmethod
    def from_bytes(data: bytes) -> NodeMetadata:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class FleetStateChecksum:

    def __init__(
            self,
            other_nodes: Sequence[NodeMetadata],
            this_node: Optional[NodeMetadata]
    ):
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class MetadataRequest:

    def __init__(
            self,
            fleet_state_checksum: FleetStateChecksum,
            announce_nodes: Sequence[NodeMetadata],
    ):
        ...

    fleet_state_checksum: FleetStateChecksum

    announce_nodes: List[NodeMetadata]

    @staticmethod
    def from_bytes(data: bytes) -> MetadataRequest:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class MetadataResponsePayload:

    def __init__(self, timestamp_epoch: int, announce_nodes: Sequence[NodeMetadata]):
        ...

    timestamp_epoch: int

    announce_nodes: List[NodeMetadata]


@final
class MetadataResponse:

    def __init__(self, signer: Signer, payload: MetadataResponsePayload):
        ...

    def verify(self, verifying_pk: PublicKey) -> MetadataResponsePayload:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> MetadataResponse:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class AuthenticatedData:

    def __init__(self, public_key: DkgPublicKey, conditions: Conditions):
        ...

    public_key: DkgPublicKey

    conditions: Conditions

    def aad(self) -> bytes:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> AuthenticatedData:
        ...

    def __bytes__(self) -> bytes:
        ...


def encrypt_for_dkg(
        data: bytes,
        public_key: DkgPublicKey,
        conditions: Conditions
) -> Tuple[
    Ciphertext, AuthenticatedData]:
    ...


@final
class AccessControlPolicy:

    def __init__(self, auth_data: AuthenticatedData, authorization: bytes):
        ...

    public_key: DkgPublicKey

    conditions: Conditions

    authorization: bytes

    def aad(self) -> bytes:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> AccessControlPolicy:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class ThresholdMessageKit:

    def __init__(self, ciphertext: Ciphertext, acp: AccessControlPolicy):
        ...

    acp: AccessControlPolicy

    ciphertext_header: CiphertextHeader

    def decrypt_with_shared_secret(self, shared_secret: SharedSecret) -> bytes:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> ThresholdMessageKit:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class ThresholdDecryptionRequest:

    def __init__(
            self,
            ritual_id: int,
            variant: FerveoVariant,
            ciphertext_header: CiphertextHeader,
            acp: AccessControlPolicy,
            context: Optional[Context]
    ):
        ...

    ritual_id: int

    acp: AccessControlPolicy

    context: Optional[Context]

    variant: FerveoVariant

    ciphertext_header: CiphertextHeader

    def encrypt(
            self,
            shared_secret: SessionSharedSecret,
            requester_public_key: SessionStaticKey
    ) -> EncryptedThresholdDecryptionRequest:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> ThresholdDecryptionRequest:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class EncryptedThresholdDecryptionRequest:
    ritual_id: int

    requester_public_key: SessionStaticKey

    def decrypt(
            self,
            shared_secret: SessionSharedSecret
    ) -> ThresholdDecryptionRequest:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> EncryptedThresholdDecryptionRequest:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class ThresholdDecryptionResponse:

    def __init__(self, ritual_id: int, decryption_share: bytes):
        ...

    decryption_share: bytes

    ritual_id: int

    def encrypt(
            self,
            shared_secret: SessionSharedSecret
    ) -> EncryptedThresholdDecryptionResponse:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> ThresholdDecryptionResponse:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class EncryptedThresholdDecryptionResponse:
    ritual_id: int

    def decrypt(
            self,
            shared_secret: SessionSharedSecret
    ) -> ThresholdDecryptionResponse:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> EncryptedThresholdDecryptionResponse:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class SessionSharedSecret:
    ...


@final
class SessionStaticKey:

    @staticmethod
    def from_bytes(data: bytes) -> SessionStaticKey:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class SessionStaticSecret:

    @staticmethod
    def random() -> SessionStaticSecret:
        ...

    def public_key(self) -> SessionStaticKey:
        ...

    def derive_shared_secret(
            self,
            their_public_key: SessionStaticKey
    ) -> SessionSharedSecret:
        ...


@final
class SessionSecretFactory:

    @staticmethod
    def random() -> SessionSecretFactory:
        ...

    @staticmethod
    def seed_size() -> int:
        ...

    @staticmethod
    def from_secure_randomness(seed: bytes) -> SessionSecretFactory:
        ...

    def make_key(self, label: bytes) -> SessionStaticSecret:
        ...


#
# Signature request/response types
#

class SignatureRequestType:
    USEROP: int = 0
    PACKED_USER_OP: int = 1 


class AAVersion:
    V08: str = "0.8.0"
    MDT: str = "mdt"


class UserOperation:
    """UserOperation for signature requests."""
    
    def __init__(
        self,
        sender: str,
        nonce: int,
        init_code: bytes = b"",
        call_data: bytes = b"",
        call_gas_limit: int = 0,
        verification_gas_limit: int = 0,
        pre_verification_gas: int = 0,
        max_fee_per_gas: int = 0,
        max_priority_fee_per_gas: int = 0,
        paymaster: Optional[str] = None,
        paymaster_verification_gas_limit: int = 0,
        paymaster_post_op_gas_limit: int = 0,
        paymaster_data: bytes = b"",
    ) -> None:
        """Create a new UserOperation with u128 gas limits."""
        ...
    
    @property
    def sender(self) -> str:
        """Address of the sender (smart contract account)."""
        ...
    
    @property
    def nonce(self) -> int:
        """Nonce for replay protection."""
        ...
    
    @property
    def init_code(self) -> bytes:
        """Factory and data for account creation."""
        ...
    
    @property
    def call_data(self) -> bytes:
        """The calldata to execute."""
        ...
    
    @property
    def call_gas_limit(self) -> int:
        """Gas limit for the call (u128 value)."""
        ...
    
    @property
    def verification_gas_limit(self) -> int:
        """Gas limit for verification (u128 value)."""
        ...
    
    @property
    def pre_verification_gas(self) -> int:
        """Gas to cover overhead (u128 value)."""
        ...
    
    @property
    def max_fee_per_gas(self) -> int:
        """Maximum fee per gas unit (u128 value)."""
        ...
    
    @property
    def max_priority_fee_per_gas(self) -> int:
        """Maximum priority fee per gas unit (u128 value)."""
        ...
    
    @property
    def paymaster(self) -> Optional[str]:
        """Paymaster address (optional)."""
        ...
    
    @property
    def paymaster_verification_gas_limit(self) -> int:
        """Gas limit for paymaster verification (u128 value)."""
        ...
    
    @property
    def paymaster_post_op_gas_limit(self) -> int:
        """Gas limit for paymaster post-operation (u128 value)."""
        ...
    
    @property
    def paymaster_data(self) -> bytes:
        """Paymaster-specific data."""
        ...
    
    def __bytes__(self) -> bytes:
        """Serialize to bytes."""
        ...
    
    @staticmethod
    def from_bytes(data: bytes) -> 'UserOperation':
        """Deserialize from bytes."""
        ...


class UserOperationSignatureRequest:

    def __init__(
        self,
        user_op: UserOperation,
        cohort_id: int,
        chain_id: int,
        aa_version: str,
        context: Optional[Context]
    ):
        ...

    @property
    def user_op(self) -> UserOperation:
        ...

    @property
    def cohort_id(self) -> int:
        ...

    @property
    def chain_id(self) -> int:
        ...

    @property
    def aa_version(self) -> str:
        ...

    @property
    def context(self) -> Optional[Context]:
        ...

    @property
    def signature_type(self) -> int:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> UserOperationSignatureRequest:
        ...

    def __bytes__(self) -> bytes:
        ...


class PackedUserOperation:
    """Packed UserOperation for optimized format with u128 gas limits."""
    
    def __init__(
        self,
        sender: str,
        nonce: int,
        init_code: bytes,
        call_data: bytes,
        account_gas_limits: bytes,
        pre_verification_gas: int,
        gas_fees: bytes,
        paymaster_and_data: bytes,
    ) -> None:
        """Create a new PackedUserOperation with u128 pre_verification_gas."""
        ...
    
    @staticmethod
    def from_user_operation(user_op: UserOperation) -> 'PackedUserOperation':
        """Create a PackedUserOperation from a UserOperation."""
        ...
    
    @staticmethod
    def _pack_account_gas_limits(call_gas_limit: int, verification_gas_limit: int) -> bytes:
        """Pack account gas limits into a 32-byte value (u128 values)."""
        ...
    
    @staticmethod
    def _pack_gas_fees(max_fee_per_gas: int, max_priority_fee_per_gas: int) -> bytes:
        """Pack gas fees into a 32-byte value (u128 values)."""
        ...
    
    @staticmethod
    def _pack_paymaster_and_data(
        paymaster: Optional[str],
        paymaster_verification_gas_limit: int,
        paymaster_post_op_gas_limit: int,
        paymaster_data: bytes,
    ) -> bytes:
        """Pack paymaster and data with u128 gas limits."""
        ...
    
    def to_eip712_struct(self, aa_version: str, chain_id: int) -> Dict[str, Any]:
        """Convert to EIP-712 struct format."""
        ...
    
    def _to_eip712_message(self, aa_version: str) -> Dict[str, Any]:
        """Convert to EIP-712 message format."""
        ...
    
    def _get_domain(self, aa_version: str, chain_id: int) -> Dict[str, Any]:
        """Get the EIP-712 domain."""
        ...
    
    @property
    def sender(self) -> str:
        """Address of the sender (smart contract account)."""
        ...
    
    @property
    def nonce(self) -> int:
        """Nonce for replay protection."""
        ...
    
    @property
    def init_code(self) -> bytes:
        """Factory and data for account creation."""
        ...
    
    @property
    def call_data(self) -> bytes:
        """The calldata to execute."""
        ...
    
    @property
    def account_gas_limits(self) -> bytes:
        """Packed gas limits (verification gas limit << 128 | call gas limit)."""
        ...
    
    @property
    def pre_verification_gas(self) -> int:
        """Gas to cover overhead (u128 value)."""
        ...
    
    @property
    def gas_fees(self) -> bytes:
        """Packed gas fees (max priority fee << 128 | max fee)."""
        ...
    
    @property
    def paymaster_and_data(self) -> bytes:
        """Packed paymaster data."""
        ...
    
    def __bytes__(self) -> bytes:
        """Serialize to bytes."""
        ...
    
    @staticmethod
    def from_bytes(data: bytes) -> 'PackedUserOperation':
        """Deserialize from bytes."""
        ...


class SignedPackedUserOperation:
    """Signed Packed UserOperation - combines a PackedUserOperation with a signature."""
    
    def __init__(
        self,
        operation: PackedUserOperation,
        signature: bytes,
    ) -> None:
        """Create a new SignedPackedUserOperation."""
        ...
    
    @property
    def operation(self) -> PackedUserOperation:
        """The packed user operation without signature."""
        ...
    
    @property
    def signature(self) -> bytes:
        """The signature over the operation."""
        ...
    
    def into_parts(self) -> Tuple[PackedUserOperation, bytes]:
        """Returns the operation and signature as separate components."""
        ...
    
    def to_eip712_struct(self, aa_version: str, chain_id: int) -> Dict[str, Any]:
        """Convert to EIP-712 struct format."""
        ...
    
    def _to_eip712_message(self, aa_version: str) -> Dict[str, Any]:
        """Convert to EIP-712 message format."""
        ...
    
    def _get_domain(self, aa_version: str, chain_id: int) -> Dict[str, Any]:
        """Get the EIP-712 domain."""
        ...
    
    def __bytes__(self) -> bytes:
        """Serialize to bytes."""
        ...
    
    @staticmethod
    def from_bytes(data: bytes) -> 'SignedPackedUserOperation':
        """Deserialize from bytes."""
        ...


class PackedUserOperationSignatureRequest:

    def __init__(
        self,
        packed_user_op: PackedUserOperation,
        cohort_id: int,
        chain_id: int,
        aa_version: str,
        context: Optional[Context]
    ):
        ...

    @property
    def packed_user_op(self) -> PackedUserOperation:
        ...

    @property
    def cohort_id(self) -> int:
        ...

    @property
    def chain_id(self) -> int:
        ...

    @property
    def aa_version(self) -> str:
        ...

    @property
    def context(self) -> Optional[Context]:
        ...

    @property
    def signature_type(self) -> int:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> PackedUserOperationSignatureRequest:
        ...

    def __bytes__(self) -> bytes:
        ...


class SignatureResponse:
    """Response object containing signature hash, signature bytes, and type."""
    
    def __init__(self, hash: bytes, signature: bytes, signature_type: int) -> None:
        """Create a new SignatureResponse."""
        ...
    
    @property
    def hash(self) -> bytes:
        """Get the hash that was signed."""
        ...
    
    @property
    def signature(self) -> bytes:
        """Get the signature bytes."""
        ...
    
    @property
    def signature_type(self) -> int:
        """Get the signature type as integer."""
        ...
    
    @staticmethod
    def from_bytes(data: bytes) -> SignatureResponse:
        """Deserialize from bytes."""
        ...
    
    def __bytes__(self) -> bytes:
        """Serialize to bytes."""
        ...


def deserialize_signature_request(data: bytes) -> Union[UserOperationSignatureRequest, PackedUserOperationSignatureRequest]:
    """Utility function to deserialize any signature request from bytes and return the specific type directly."""
    ...
