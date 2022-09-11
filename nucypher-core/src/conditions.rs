use alloc::boxed::Box;

use serde::{Deserialize, Serialize};
use umbral_pre::serde_bytes;

/// Reencryption conditions.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Conditions(#[serde(with = "serde_bytes::as_base64")] Box<[u8]>);

impl Conditions {
    /// Creates a new conditions object.
    pub fn new(conditions: &[u8]) -> Self {
        Self(conditions.into())
    }
}

impl AsRef<[u8]> for Conditions {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Box<[u8]>> for Conditions {
    fn from(source: Box<[u8]>) -> Self {
        Self(source)
    }
}

/// Context for reencryption conditions.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Context(#[serde(with = "serde_bytes::as_base64")] Box<[u8]>);

impl Context {
    /// Creates a new context object.
    pub fn new(context: &[u8]) -> Self {
        Self(context.into())
    }
}

impl AsRef<[u8]> for Context {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<Box<[u8]>> for Context {
    fn from(source: Box<[u8]>) -> Self {
        Self(source)
    }
}
