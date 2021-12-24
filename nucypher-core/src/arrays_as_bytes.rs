// Helper functions to serialize/deserialize byte arrays (`[u8; N]`) as bytestrings.
// By default, `serde` serializes them as lists of integers, which in case of MessagePack
// leads to every value >127 being prepended with a `\xcc`.
// `serde_bytes` crate could help with that, but at the moment it only works with slices.

use core::convert::TryInto;
use core::fmt;

use serde::{de, Deserializer, Serializer};

pub(crate) fn serialize<S, const N: usize>(obj: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
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

pub(crate) fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    deserializer.deserialize_bytes(BytesVisitor::<N>())
}
