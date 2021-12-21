use alloc::boxed::Box;
use core::convert::TryInto;
use core::fmt;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

/// The object can be serialized to a byte array.
pub trait SerializableToBytes {
    /// Serializes the object.
    fn to_bytes(&self) -> Box<[u8]>;
}

/// The object can be deserialized from a byte array.
pub trait DeserializableFromBytes<'a>: Sized {
    /// Deserializes the object.
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, rmp_serde::decode::Error>;
}

pub(crate) fn standard_serialize<T>(obj: &T) -> Box<[u8]>
where
    T: Serialize,
{
    // Note: we are using a binary format here.
    // This means that `u8` arrays will be serialized as bytestrings.
    // If a text format is used at some point, one will have to write
    // a custom serializer for those because `serde` serializes them as vectors of integers.
    rmp_serde::to_vec(obj).unwrap().into_boxed_slice()
}

fn standard_deserialize<'a, T>(bytes: &'a [u8]) -> Result<T, rmp_serde::decode::Error>
where
    T: Deserialize<'a>,
{
    rmp_serde::from_read_ref(bytes)
}

/// This is a versioned protocol object.
pub trait ProtocolObject {
    // fn version() -> (u16, u16) {}
}

impl<T: ProtocolObject + Serialize> SerializableToBytes for T {
    fn to_bytes(&self) -> Box<[u8]> {
        standard_serialize(self)
    }
}

impl<'a, T: ProtocolObject + Deserialize<'a>> DeserializableFromBytes<'a> for T {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, rmp_serde::decode::Error> {
        standard_deserialize(bytes)
    }
}

// Helper functions to serialize/deserialize byte arrays (`[u8; N]`) as bytestrings.
// By default, `serde` serializes them as lists of integers, which in case of MessagePack
// leads to every value >127 being prepended with a `\xcc`.
// `serde_bytes` crate could help with that, but at the moment
// it only works with `&[u8]` and `Vec<u8>`.

pub(crate) fn serde_serialize_as_bytes<S, const N: usize>(
    obj: &[u8; N],
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(obj)
}

struct BytesVisitor<const N: usize>();

impl<'de, const N: usize> de::Visitor<'de> for BytesVisitor<N> {
    type Value = [u8; N];

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Byte array of length {}", N)
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        v.try_into().map_err(de::Error::custom)
    }
}

pub(crate) fn serde_deserialize_as_bytes<'de, D, const N: usize>(
    deserializer: D,
) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(BytesVisitor::<N>())
}
