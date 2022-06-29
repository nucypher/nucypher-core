// Helper functions to serialize/deserialize byte arrays (`[u8; N]`) as bytestrings.
// By default, `serde` serializes them as lists of integers, which in case of MessagePack
// leads to every value >127 being prepended with a `\xcc`.
// `serde_bytes` crate could help with that, but at the moment it only works with slices.

use core::convert::TryInto;
use core::fmt;

use serde::{de, Deserializer, Serializer};

//
// Serialization
//

/// Types that can be serialized via this module.
pub(crate) trait SerializeAsBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer;
}

impl<const N: usize> SerializeAsBytes for [u8; N] {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self)
    }
}

//
// Deserialization
//

/// Types that can be deserialized via this module.
pub(crate) trait DeserializeAsBytes<'de>: Sized {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>;
}

impl<'de, const N: usize> DeserializeAsBytes<'de> for [u8; N] {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<const N: usize>();

        impl<'de, const N: usize> de::Visitor<'de> for BytesVisitor<N> {
            type Value = [u8; N];

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "byte array of length {}", N)
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                v.try_into().map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_bytes(BytesVisitor::<N>())
    }
}

//
// Dispatcher functions
//

pub(crate) fn serialize<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: ?Sized + SerializeAsBytes,
    S: Serializer,
{
    SerializeAsBytes::serialize(obj, serializer)
}

pub(crate) fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    T: DeserializeAsBytes<'de>,
    D: Deserializer<'de>,
{
    DeserializeAsBytes::deserialize(deserializer)
}
