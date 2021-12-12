use alloc::boxed::Box;

use serde::{Deserialize, Serialize};

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
