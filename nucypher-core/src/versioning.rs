use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};

pub(crate) fn messagepack_serialize<T>(obj: &T) -> Box<[u8]>
where
    T: Serialize,
{
    // Note: we are using a binary format here.
    // This means that `u8` arrays will be serialized as bytestrings.
    // If a text format is used at some point, one will have to write
    // a custom serializer for those because `serde` serializes them as vectors of integers.

    // Panic on serialization error.
    // For this library, a serialization error will certainly indicate
    // some irrecoverable logical problem, so there is no sense in propagating it.
    rmp_serde::to_vec(obj)
        .map(|vec| vec.into_boxed_slice())
        .expect("Error serializing into MessagePack")
}

pub(crate) fn messagepack_deserialize<'a, T>(bytes: &'a [u8]) -> Result<T, String>
where
    T: Deserialize<'a>,
{
    rmp_serde::from_read_ref(bytes).map_err(|err| format!("{}", err))
}

struct ProtocolObjectHeader {
    brand: [u8; 4],
    major_version: u16,
    minor_version: u16,
}

impl ProtocolObjectHeader {
    fn to_bytes(&self) -> [u8; 8] {
        let mut header = [0u8; 8];
        header[..4].copy_from_slice(&self.brand);
        header[4..6].copy_from_slice(&self.major_version.to_be_bytes());
        header[6..].copy_from_slice(&self.minor_version.to_be_bytes());
        header
    }

    fn from_bytes(bytes: &[u8; 8]) -> Self {
        Self {
            brand: [bytes[0], bytes[1], bytes[2], bytes[3]],
            major_version: u16::from_be_bytes([bytes[4], bytes[5]]),
            minor_version: u16::from_be_bytes([bytes[6], bytes[7]]),
        }
    }

    fn from_type<'a, T>() -> Self
    where
        T: ProtocolObjectInner<'a>,
    {
        let (major, minor) = T::version();
        Self {
            brand: T::brand(),
            major_version: major,
            minor_version: minor,
        }
    }
}

#[derive(Debug)]
pub enum DeserializationError {
    TooShort {
        expected: usize,
        received: usize,
    },
    IncorrectHeader {
        expected: [u8; 4],
        received: [u8; 4],
    },
    MajorVersionMismatch {
        expected: u16,
        received: u16,
    },
    UnsupportedMinorVersion {
        expected: u16,
        received: u16,
    },
    BadPayload {
        error_msg: String,
    },
}

impl fmt::Display for DeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { expected, received } => write!(
                f,
                "bytestring too short: expected {} bytes, got {}",
                expected, received
            ),
            Self::IncorrectHeader { expected, received } => write!(
                f,
                "incorrect header: expected {:?}, got {:?}",
                expected, received
            ),
            Self::MajorVersionMismatch { expected, received } => write!(
                f,
                "differing major version: expected {}, got {}",
                expected, received
            ),
            Self::UnsupportedMinorVersion { expected, received } => write!(
                f,
                "unsupported minor version: expected <={}, got {}",
                expected, received
            ),
            Self::BadPayload { error_msg } => {
                write!(f, "payload deserialization failed: {}", error_msg)
            }
        }
    }
}

// The "private" part of `ProtocolObject` allowing one to modify implementation
// without incurring backward incompatible API change.
// It is `pub` (has to be, otherwise Rust complains), but this module is not exported,
// so this trait can't be used by an external crate, and it is not documented.
pub trait ProtocolObjectInner<'a>: Serialize + Deserialize<'a> {
    /// Returns the major and the minor version of the object.
    ///
    /// It must be possible to deserialize an object with version X.Y
    /// in the code where the declared version is X.Z, as long as Z >= Y.
    fn version() -> (u16, u16);

    /// A unique object tag.
    fn brand() -> [u8; 4];

    fn unversioned_to_bytes(&self) -> Box<[u8]>;

    fn unversioned_from_bytes(minor_version: u16, bytes: &'a [u8]) -> Option<Result<Self, String>>;
}

/// This is a versioned protocol object.
pub trait ProtocolObject<'a>: ProtocolObjectInner<'a> {
    // The version of the object as a tuple `(major, minor)`
    /// supported by the current implementation.
    fn version() -> (u16, u16) {
        // Expose the private trait's method,
        // since it can be useful to know the object's expected version
        // (e.g. to display on a status page).
        <Self as ProtocolObjectInner>::version()
    }

    /// Serializes the object.
    fn to_bytes(&self) -> Box<[u8]> {
        let header_bytes = ProtocolObjectHeader::from_type::<Self>().to_bytes();
        let unversioned_bytes = Self::unversioned_to_bytes(self);

        let mut result = Vec::with_capacity(header_bytes.len() + unversioned_bytes.len());
        result.extend(header_bytes);
        result.extend(unversioned_bytes.iter());
        result.into_boxed_slice()
    }

    /// Attempts to deserialize the object.
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, DeserializationError> {
        if bytes.len() < 8 {
            return Err(DeserializationError::TooShort {
                expected: 8,
                received: bytes.len(),
            });
        }
        let mut header_bytes = [0u8; 8];
        header_bytes.copy_from_slice(&bytes[..8]);
        let header = ProtocolObjectHeader::from_bytes(&header_bytes);

        let reference_header = ProtocolObjectHeader::from_type::<Self>();

        if header.brand != reference_header.brand {
            return Err(DeserializationError::IncorrectHeader {
                expected: reference_header.brand,
                received: header.brand,
            });
        }

        if header.major_version != reference_header.major_version {
            return Err(DeserializationError::MajorVersionMismatch {
                expected: reference_header.major_version,
                received: header.major_version,
            });
        }

        if header.minor_version > reference_header.minor_version {
            return Err(DeserializationError::UnsupportedMinorVersion {
                expected: reference_header.minor_version,
                received: header.minor_version,
            });
        }

        let result = match Self::unversioned_from_bytes(header.minor_version, &bytes[8..]) {
            Some(result) => result,
            // The type must support all minor versions below or equal to the current one,
            // otherwise it should be the major version change.
            // This is a bug, so we panic here.
            None => panic!("minor version {} is not supported", header.minor_version),
        };

        result.map_err(|msg| DeserializationError::BadPayload { error_msg: msg })
    }
}
