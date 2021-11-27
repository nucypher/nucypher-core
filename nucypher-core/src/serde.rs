use alloc::boxed::Box;

use serde::{Deserialize, Serialize};

pub trait SerializableToBytes {
    fn to_bytes(&self) -> Box<[u8]>;
}

impl<T: Serialize> SerializableToBytes for T {
    fn to_bytes(&self) -> Box<[u8]> {
        rmp_serde::to_vec(self).unwrap().into_boxed_slice()
    }
}

pub trait DeserializableFromBytes<'a>: Sized {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, rmp_serde::decode::Error>;
}

impl<'a, T: Deserialize<'a>> DeserializableFromBytes<'a> for T {
    fn from_bytes(bytes: &'a [u8]) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_read_ref(bytes)
    }
}

pub trait Versioned<'a>: SerializableToBytes + DeserializableFromBytes<'a> {}

// We need to pick some serialization method of the multitude Serde provides.
// Using MessagePack for now.
pub(crate) fn standard_serialize<T: Serialize>(obj: &T) -> Box<[u8]> {
    rmp_serde::to_vec(obj).unwrap().into_boxed_slice()
}

pub(crate) fn standard_deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> T {
    rmp_serde::from_read_ref(bytes).unwrap()
}
