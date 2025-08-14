from typing import Sequence, final

@final
class Keypair:
    @staticmethod
    def random() -> Keypair:
        ...

    @staticmethod
    def from_secure_randomness(secure_randomness: bytes) -> Keypair:
        ...

    @staticmethod
    def secure_randomness_size() -> int:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> Keypair:
        ...

    def __bytes__(self) -> bytes:
        ...

    def public_key(self) -> FerveoPublicKey:
        ...


@final
class FerveoPublicKey:
    @staticmethod
    def from_bytes(data: bytes) -> FerveoPublicKey:
        ...

    def __bytes__(self) -> bytes:
        ...

    def __hash__(self) -> int:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...

    def __eq__(self, other: object) -> bool:
        ...


@final
class Validator:

    def __init__(self, address: str, public_key: FerveoPublicKey, share_index: int):
        ...

    address: str

    public_key: FerveoPublicKey

    share_index: int


@final
class Transcript:
    @staticmethod
    def from_bytes(data: bytes) -> Transcript:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class DkgPublicKey:
    @staticmethod
    def from_bytes(data: bytes) -> DkgPublicKey:
        ...

    def __bytes__(self) -> bytes:
        ...

    @staticmethod
    def serialized_size() -> int:
        ...


@final
class ValidatorMessage:

    def __init__(
            self,
            validator: Validator,
            transcript: Transcript,
    ):
        ...

    validator: Validator
    transcript: Transcript


@final
class Dkg:

    def __init__(
            self,
            tau: int,
            shares_num: int,
            security_threshold: int,
            validators: Sequence[Validator],
            me: Validator,
    ):
        ...

    public_key: DkgPublicKey

    def generate_transcript(self) -> Transcript:
        ...

    def aggregate_transcripts(
            self,
            messages: Sequence[ValidatorMessage]
    ) -> AggregatedTranscript:
        ...

    def generate_handover_transcript(
        self,
        aggregate: AggregatedTranscript,
        handover_slot_index: int,
        incoming_validator_keypair: Keypair,
    ) -> HandoverTranscript:
        ...

@final
class Ciphertext:
    header: CiphertextHeader
    payload: bytes

    @staticmethod
    def from_bytes(data: bytes) -> Ciphertext:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class CiphertextHeader:
    @staticmethod
    def from_bytes(data: bytes) -> CiphertextHeader:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class DecryptionShareSimple:
    @staticmethod
    def from_bytes(data: bytes) -> DecryptionShareSimple:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class DecryptionSharePrecomputed:
    @staticmethod
    def from_bytes(data: bytes) -> DecryptionSharePrecomputed:
        ...

    def __bytes__(self) -> bytes:
        ...

@final
class HandoverTranscript:
    @staticmethod
    def from_bytes(data: bytes) -> HandoverTranscript:
        ...

    def __bytes__(self) -> bytes:
        ...

@final
class AggregatedTranscript:
    public_key: DkgPublicKey

    def __init__(self, messages: Sequence[ValidatorMessage]):
        ...

    def verify(self, validators_num: int, messages: Sequence[ValidatorMessage]) -> bool:
        ...

    def create_decryption_share_simple(
            self,
            dkg: Dkg,
            ciphertext_header: CiphertextHeader,
            aad: bytes,
            validator_keypair: Keypair
    ) -> DecryptionShareSimple:
        ...

    def create_decryption_share_precomputed(
            self,
            dkg: Dkg,
            ciphertext_header: CiphertextHeader,
            aad: bytes,
            validator_keypair: Keypair,
            selected_validators: Sequence[Validator],
    ) -> DecryptionSharePrecomputed:
        ...

    def finalize_handover(
        self,
        handover_transcript: HandoverTranscript,
        validator_keypair: Keypair,
    ) -> AggregatedTranscript:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> AggregatedTranscript:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class SharedSecret:

    @staticmethod
    def from_bytes(data: bytes) -> SharedSecret:
        ...

    def __bytes__(self) -> bytes:
        ...


@final
class FerveoVariant:
    Simple: FerveoVariant
    Precomputed: FerveoVariant

    def __eq__(self, other: object) -> bool:
        ...

    def __hash__(self) -> int:
        ...


def encrypt(message: bytes, aad: bytes, dkg_public_key: DkgPublicKey) -> Ciphertext:
    ...


def combine_decryption_shares_simple(
        decryption_shares: Sequence[DecryptionShareSimple],
) -> SharedSecret:
    ...


def combine_decryption_shares_precomputed(
        decryption_shares: Sequence[DecryptionSharePrecomputed],
) -> SharedSecret:
    ...


def decrypt_with_shared_secret(
        ciphertext: Ciphertext,
        aad: bytes,
        shared_secret: SharedSecret,
) -> bytes:
    ...


class ThresholdEncryptionError(Exception):
    pass


class InvalidDkgStateToDeal(Exception):
    pass


class InvalidDkgStateToAggregate(Exception):
    pass


class InvalidDkgStateToVerify(Exception):
    pass


class InvalidDkgStateToIngest(Exception):
    pass


class DealerNotInValidatorSet(Exception):
    pass


class UnknownDealer(Exception):
    pass


class DuplicateDealer(Exception):
    pass


class InvalidPvssTranscript(Exception):
    pass


class InsufficientTranscriptsForAggregate(Exception):
    pass


class InvalidDkgPublicKey(Exception):
    pass


class InsufficientValidators(Exception):
    pass


class InvalidTranscriptAggregate(Exception):
    pass


class ValidatorPublicKeyMismatch(Exception):
    pass


class SerializationError(Exception):
    pass
