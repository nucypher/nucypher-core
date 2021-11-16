use alloc::boxed::Box;

use serde::{Deserialize, Serialize};

// We need to pick some serialization method of the multitude Serde provides.
// Using MessagePack for now.
pub(crate) fn standard_serialize<T: Serialize>(obj: &T) -> Box<[u8]> {
    rmp_serde::to_vec(obj).unwrap().into_boxed_slice()
}

pub(crate) fn standard_deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> T {
    rmp_serde::from_read_ref(bytes).unwrap()
}
