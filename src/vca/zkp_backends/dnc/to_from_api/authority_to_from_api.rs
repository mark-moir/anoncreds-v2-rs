// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::vca::interfaces::types as api;
use crate::vca::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use saver::keygen::DecryptionKey as SaverDecryptionKey;
use saver::keygen::SecretKey     as SaverSecretKey;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381,Fr};
// ------------------------------------------------------------------------------

impl VcaTryFrom<AuthorityPublicSetupData> for api::AuthorityPublicData {
    fn vca_try_from(x: AuthorityPublicSetupData) -> VCAResult<api::AuthorityPublicData> {
        Ok(api::AuthorityPublicData(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::AuthorityPublicData> for AuthorityPublicSetupData {
    fn vca_try_from(x: &api::AuthorityPublicData) -> VCAResult<AuthorityPublicSetupData> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<SaverSecretKey::<Fr>> for api::AuthoritySecretData {
    fn vca_try_from(x: SaverSecretKey::<Fr>) -> VCAResult<api::AuthoritySecretData> {
        Ok(api::AuthoritySecretData(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::AuthoritySecretData> for SaverSecretKey::<Fr> {
    fn vca_try_from(x: &api::AuthoritySecretData) -> VCAResult<SaverSecretKey::<Fr>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<SaverDecryptionKey::<Bls12_381>> for api::AuthorityDecryptionKey {
    fn vca_try_from(x: SaverDecryptionKey::<Bls12_381>) -> VCAResult<api::AuthorityDecryptionKey> {
        Ok(api::AuthorityDecryptionKey(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::AuthorityDecryptionKey> for SaverDecryptionKey::<Bls12_381> {
    fn vca_try_from(x: &api::AuthorityDecryptionKey) -> VCAResult<SaverDecryptionKey::<Bls12_381>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<(Fr, G1)> for api::DecryptionProof {
    fn vca_try_from(x: (Fr, G1)) -> VCAResult<api::DecryptionProof> {
        Ok(api::DecryptionProof(to_opaque_ark(&x)?))
    }
}

impl VcaTryFrom<&api::DecryptionProof> for (Fr, G1) {
    fn vca_try_from(x: &api::DecryptionProof) -> VCAResult<(Fr, G1)> {
        from_opaque_ark(&x.0)
    }
}

