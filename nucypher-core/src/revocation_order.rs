use serde::{Deserialize, Serialize};
use umbral_pre::{PublicKey, SerializableToArray, Signature, Signer};

use crate::address::Address;
use crate::key_frag::EncryptedKeyFrag;
use crate::serde::{ProtocolObject, SerializableToBytes};

/// Represents a string used by characters to perform a revocation on a specific Ursula.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RevocationOrder {
    ursula_address: Address,
    encrypted_kfrag: EncryptedKeyFrag,
    signature: Signature,
}

impl RevocationOrder {
    /// Create and sign a new revocation order.
    pub fn new(
        signer: &Signer,
        ursula_address: &Address,
        encrypted_kfrag: &EncryptedKeyFrag,
    ) -> Self {
        Self {
            ursula_address: *ursula_address,
            encrypted_kfrag: encrypted_kfrag.clone(),
            signature: signer.sign(
                &[
                    ursula_address.to_array().as_slice(),
                    &encrypted_kfrag.to_bytes(),
                ]
                .concat(),
            ),
        }
    }

    /// Verifies the revocation order against Alice's key.
    pub fn verify_signature(&self, alice_verifying_key: &PublicKey) -> bool {
        // TODO: return an Option of something instead of returning `bool`?
        let message = [
            self.ursula_address.to_array().as_slice(),
            &self.encrypted_kfrag.to_bytes(),
        ]
        .concat();
        self.signature.verify(alice_verifying_key, &message)
    }
}

impl ProtocolObject for RevocationOrder {}
