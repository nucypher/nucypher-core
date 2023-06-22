from typing import Sequence


class Keypair:
    @staticmethod
    def random() -> Keypair:
        ...

    @staticmethod
    def from_secure_randomness(data: bytes) -> Keypair:
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


class FerveoPublicKey:
    @staticmethod
    def from_bytes(data: bytes) -> FerveoPublicKey:
        ...

    def __bytes__(self) -> bytes:
        ...

    def __hash__(self) -> int:
        ...


class Validator:

    def __init__(self, address: str, public_key: FerveoPublicKey):
        ...

    address: str

    public_key: FerveoPublicKey


class Transcript:
    @staticmethod
    def from_bytes(data: bytes) -> Transcript:
        ...

    def __bytes__(self) -> bytes:
        ...


class DkgPublicKey:
    @staticmethod
    def from_bytes(data: bytes) -> DkgPublicKey:
        ...

    def __bytes__(self) -> bytes:
        ...


class ValidatorMessage:

    def __init__(
            self,
            validator: Validator,
            transcript: Transcript,
    ):
        ...

    validator: Validator
    transcript: Transcript


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

    def aggregate_transcripts(self, messages: Sequence[ValidatorMessage]) -> AggregatedTranscript:
        ...


class Ciphertext:
    @staticmethod
    def from_bytes(data: bytes) -> Ciphertext:
        ...

    def __bytes__(self) -> bytes:
        ...


class DecryptionShareSimple:
    @staticmethod
    def from_bytes(data: bytes) -> DecryptionShareSimple:
        ...

    def __bytes__(self) -> bytes:
        ...


class DecryptionSharePrecomputed:
    @staticmethod
    def from_bytes(data: bytes) -> DecryptionSharePrecomputed:
        ...

    def __bytes__(self) -> bytes:
        ...


class AggregatedTranscript:

    def __init__(self, messages: Sequence[ValidatorMessage]):
        ...

    def verify(self, shares_num: int, messages: Sequence[ValidatorMessage]) -> bool:
        ...

    def create_decryption_share_simple(
            self,
            dkg: Dkg,
            ciphertext: Ciphertext,
            aad: bytes,
            validator_keypair: Keypair
    ) -> DecryptionShareSimple:
        ...

    def create_decryption_share_precomputed(
            self,
            dkg: Dkg,
            ciphertext: Ciphertext,
            aad: bytes,
            validator_keypair: Keypair
    ) -> DecryptionSharePrecomputed:
        ...

    @staticmethod
    def from_bytes(data: bytes) -> AggregatedTranscript:
        ...

    def __bytes__(self) -> bytes:
        ...


class SharedSecret:

    @staticmethod
    def from_bytes(data: bytes) -> SharedSecret:
        ...

    def __bytes__(self) -> bytes:
        ...


def encrypt(message: bytes, add: bytes, dkg_public_key: DkgPublicKey) -> Ciphertext:
    ...


def combine_decryption_shares_simple(
        decryption_shares: Sequence[DecryptionShareSimple],
) -> bytes:
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


class InvalidShareNumberParameter(Exception):
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


class ValidatorsNotSorted(Exception):
    pass


class ValidatorPublicKeyMismatch(Exception):
    pass


class SerializationError(Exception):
    pass