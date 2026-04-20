// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::{impl_vca_roundtrip_json, impl_vca_roundtrip_ark};
use crate::vca::interfaces::types as api;
use crate::vca::zkp_backends::dnc::types::*;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// ------------------------------------------------------------------------------
use bbs_plus::prelude::KeypairG2;
use bbs_plus::prelude::PublicKeyG2;
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use bbs_plus::prelude::SignatureParamsG1;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::pairing::Pairing;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DncSignerPublicSetupData {
    pub sig_params: SignatureParamsG1::<Bls12_381>,
    pub pk: PublicKeyG2<Bls12_381>,
}

impl VcaTryFrom<(SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>)> for api::SignerPublicSetupData {
    fn vca_try_from((sp, pk): (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>)) -> VCAResult<api::SignerPublicSetupData> {
        Ok(api::SignerPublicSetupData(to_opaque_ark(&DncSignerPublicSetupData { sig_params: sp, pk })?))
    }
}

impl VcaTryFrom<&api::SignerPublicSetupData> for (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>) {
    fn vca_try_from(x: &api::SignerPublicSetupData) -> VCAResult<(SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>)> {
        let inner: DncSignerPublicSetupData = from_opaque_ark(&x.0)?;
        Ok((inner.sig_params, inner.pk))
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<SecretKeyBls12_381> for api::SignerSecretData {
    fn vca_try_from(x: SecretKeyBls12_381) -> VCAResult<api::SignerSecretData> {
        Ok(api::SignerSecretData(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::SignerSecretData> for SecretKeyBls12_381 {
    fn vca_try_from(x: &api::SignerSecretData) -> VCAResult<SecretKeyBls12_381> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<SignatureG1::<Bls12_381>> for api::Signature {
    fn vca_try_from(x: SignatureG1::<Bls12_381>) -> VCAResult<api::Signature> {
        Ok(api::Signature(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::Signature> for SignatureG1::<Bls12_381> {
    fn vca_try_from(x: &api::Signature) -> VCAResult<SignatureG1::<Bls12_381>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl_vca_roundtrip_ark!(G1Affine => api::BlindInfoForSigner);

// ------------------------------------------------------------------------------

impl_vca_roundtrip_ark!(BlindInfoForSignerPayload => api::BlindInfoForSigner);

// ------------------------------------------------------------------------------

impl_vca_roundtrip_ark!(Fr => api::InfoForUnblinding);

// ------------------------------------------------------------------------------

impl<E:Pairing> VcaTryFrom<SignatureG1<E>> for api::BlindSignature {
    fn vca_try_from(x: SignatureG1<E>) -> VCAResult<api::BlindSignature> {
        Ok(api::BlindSignature(to_opaque_json(&x)?))
    }
}

impl<E: Pairing> VcaTryFrom<&api::BlindSignature> for SignatureG1<E> {
    fn vca_try_from(x: &api::BlindSignature) -> VCAResult<SignatureG1<E>> {
        from_opaque_json(&x.0)
    }
}

