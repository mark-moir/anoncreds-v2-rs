// ------------------------------------------------------------------------------
use crate::vca::VCAResult;
use crate::vca::r#impl::to_from_api::*;
use crate::vca::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::blsful::{Bls12381G2Impl, SecretKey};
// ------------------------------------------------------------------------------
use serde::*;
// ------------------------------------------------------------------------------

impl VcaTryFrom<SecretKey<Bls12381G2Impl>> for AuthoritySecretData {
    fn vca_try_from(x: SecretKey<Bls12381G2Impl>) -> VCAResult<AuthoritySecretData> {
        Ok(AuthoritySecretData(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&AuthoritySecretData> for SecretKey<Bls12381G2Impl> {
    fn vca_try_from(x: &AuthoritySecretData) -> VCAResult<SecretKey<Bls12381G2Impl>> {
        from_opaque_json(&x.0)
    }
}

impl VcaTryFrom<SecretKey<Bls12381G2Impl>> for AuthorityDecryptionKey {
    fn vca_try_from(x: SecretKey<Bls12381G2Impl>) -> VCAResult<AuthorityDecryptionKey> {
        Ok(AuthorityDecryptionKey(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&AuthorityDecryptionKey> for SecretKey<Bls12381G2Impl> {
    fn vca_try_from(x: &AuthorityDecryptionKey) -> VCAResult<SecretKey<Bls12381G2Impl>> {
        from_opaque_json(&x.0)
    }
}

