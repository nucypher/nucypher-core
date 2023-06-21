use alloc::string::String;
use core::fmt;

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

impl fmt::Display for Conditions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Conditions({})", self.0)
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

impl fmt::Display for Context {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Context({})", self.0)
    }
}
