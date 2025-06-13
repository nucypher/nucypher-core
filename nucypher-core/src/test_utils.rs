#[cfg(test)]
pub mod util {

    use ark_std::UniformRand;
    use ferveo::api::{to_bytes, DkgPublicKey, G1Affine};

    /// Generate a random DKG public key.
    pub fn random_dkg_pubkey() -> DkgPublicKey {
        let mut rng = rand::thread_rng();
        let g1 = G1Affine::rand(&mut rng);
        DkgPublicKey::from_bytes(&to_bytes(&g1).unwrap()).unwrap()
    }
}
