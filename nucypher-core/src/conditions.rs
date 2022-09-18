use alloc::string::String;

use serde::{Deserialize, Serialize};

/// Reencryption conditions.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Conditions(String);

impl Conditions {
    /// Creates a new conditions object.
    pub fn new(conditions: &str) -> Self {
        Self(conditions.into())
    }
}

impl AsRef<str> for Conditions {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<String> for Conditions {
    fn from(source: String) -> Self {
        Self(source)
    }
}

/// Context for reencryption conditions.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct Context(String);

impl Context {
    /// Creates a new context object.
    pub fn new(context: &str) -> Self {
        Self(context.into())
    }
}

impl AsRef<str> for Context {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl From<String> for Context {
    fn from(source: String) -> Self {
        Self(source)
    }
}
