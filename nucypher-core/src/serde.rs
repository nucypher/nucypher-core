use alloc::boxed::Box;

use core::fmt;
use core::marker::PhantomData;

use generic_array::{ArrayLength, GenericArray};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use typenum::Unsigned;

pub(crate) enum Representation {
    Base64,
    Hex,
}

// We cannot have a generic implementation of Serialize over everything
// that supports SerializableToArray, so we have to use this helper function
// and define implementations manually.
pub(crate) fn serde_serialize_bytes<T, S>(
    obj: &T,
    serializer: S,
    representation: Representation,
) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    if serializer.is_human_readable() {
        let repr = match representation {
            Representation::Base64 => base64::encode(obj.as_ref()),
            Representation::Hex => hex::encode(obj.as_ref()),
        };
        serializer.serialize_str(&repr)
    } else {
        serializer.serialize_bytes(obj.as_ref())
    }
}

pub(crate) fn serde_serialize_bytes_as_hex<T, S>(obj: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serde_serialize_bytes(obj, serializer, Representation::Hex)
}

pub(crate) trait DeserializableFromBytes: Sized {
    type Error;
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error>;
    fn type_name() -> &'static str;
}

struct B64Visitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for B64Visitor<T>
where
    T: DeserializableFromBytes,
    <T as DeserializableFromBytes>::Error: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "b64-encoded {} bytes", T::type_name())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = base64::decode(v).map_err(de::Error::custom)?;
        T::from_bytes(&bytes).map_err(de::Error::custom)
    }
}

struct HexVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for HexVisitor<T>
where
    T: DeserializableFromBytes,
    <T as DeserializableFromBytes>::Error: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "hex-encoded {} bytes", T::type_name())
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        let bytes = hex::decode(v).map_err(de::Error::custom)?;
        T::from_bytes(&bytes).map_err(de::Error::custom)
    }
}

struct BytesVisitor<T>(PhantomData<T>);

impl<'de, T> de::Visitor<'de> for BytesVisitor<T>
where
    T: DeserializableFromBytes,
    <T as DeserializableFromBytes>::Error: fmt::Display,
{
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", T::type_name())
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        T::from_bytes(v).map_err(de::Error::custom)
    }
}

// We cannot have a generic implementation of Deerialize over everything
// that supports DeserializableFromArray, so we have to use this helper function
// and define implementations manually.
pub(crate) fn serde_deserialize_bytes<'de, T, D>(
    deserializer: D,
    representation: Representation,
) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializableFromBytes,
    <T as DeserializableFromBytes>::Error: fmt::Display,
{
    if deserializer.is_human_readable() {
        match representation {
            Representation::Base64 => deserializer.deserialize_str(B64Visitor::<T>(PhantomData)),
            Representation::Hex => deserializer.deserialize_str(HexVisitor::<T>(PhantomData)),
        }
    } else {
        deserializer.deserialize_bytes(BytesVisitor::<T>(PhantomData))
    }
}

pub(crate) fn serde_deserialize_bytes_as_hex<'de, T, D>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializableFromBytes,
    <T as DeserializableFromBytes>::Error: fmt::Display,
{
    serde_deserialize_bytes(deserializer, Representation::Hex)
}

pub struct GenericArrayDeserializationError {
    received_size: usize,
    expected_size: usize,
}

impl fmt::Display for GenericArrayDeserializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Bytestring size mismatch: expected {} bytes, got {}",
            self.expected_size, self.received_size
        )
    }
}

impl<N> DeserializableFromBytes for GenericArray<u8, N>
where
    N: ArrayLength<u8>,
{
    type Error = GenericArrayDeserializationError;
    fn from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
        let received_size = bytes.len();
        let expected_size = <N as Unsigned>::to_usize();
        if received_size == expected_size {
            Ok(GenericArray::<u8, N>::clone_from_slice(bytes))
        } else {
            Err(GenericArrayDeserializationError {
                received_size,
                expected_size,
            })
        }
    }
    fn type_name() -> &'static str {
        "GenericArray"
    }
}

// We need to pick some serialization method of the multitude Serde provides.
// Using MessagePack for now.
pub(crate) fn standard_serialize<T: Serialize>(obj: &T) -> Box<[u8]> {
    rmp_serde::to_vec(obj).unwrap().into_boxed_slice()
}

pub(crate) fn standard_deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> T {
    rmp_serde::from_read_ref(bytes).unwrap()
}
