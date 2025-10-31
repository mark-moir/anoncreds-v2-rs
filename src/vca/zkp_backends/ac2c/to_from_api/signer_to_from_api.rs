use crate::blind::BlindCredentialRequest;
// ------------------------------------------------------------------------------
use crate::vca::VCAResult;
use crate::vca::r#impl::to_from_api::*;
use crate::vca::types::*;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::{BlindCredentialBundle, CredentialBundle, Issuer, IssuerPublic};
use crate::prelude::blsful::{Bls12381G2Impl, SecretKey};
use crate::prelude::blsful::inner_types::*;
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

// TODO: this should not be for a triple, two components of which are not AC2C-specific
impl<S: ShortGroupSignatureScheme> VcaTryFrom<(IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>)> for SignerPublicData {
    fn vca_try_from((issuer_public, sch, b_idxs): (IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>))
                    -> VCAResult<SignerPublicData> {
         Ok(SignerPublicData {
             signer_public_setup_data : SignerPublicSetupData(to_opaque_json(&issuer_public)?),
             signer_public_schema     : sch,
             signer_blinded_attr_idxs : b_idxs
         })
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&Box::<SignerPublicData>> for
    (IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>) {
    fn vca_try_from(x: &Box::<SignerPublicData>) -> VCAResult<(IssuerPublic<S>, Vec<ClaimType>, Vec<CredAttrIndex>)> {
        let ip : IssuerPublic<S> = from_opaque_json(&x.signer_public_setup_data.0)?;
        Ok((ip, x.signer_public_schema.clone(), x.signer_blinded_attr_idxs.clone()))
    }
}

// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcaTryFrom<IssuerPublic<S>> for SignerPublicSetupData {
    fn vca_try_from(x: IssuerPublic<S>) -> VCAResult<SignerPublicSetupData> {
        Ok(SignerPublicSetupData(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&SignerPublicSetupData> for IssuerPublic<S> {
    fn vca_try_from(x: &SignerPublicSetupData) -> VCAResult<IssuerPublic<S>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcaTryFrom<Issuer<S>> for SignerSecretData {
    fn vca_try_from(x: Issuer<S>) -> VCAResult<SignerSecretData> {
        Ok(SignerSecretData(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&SignerSecretData> for Issuer<S> {
    fn vca_try_from(x: &SignerSecretData) -> VCAResult<Issuer<S>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcaTryFrom<CredentialBundle<S>> for Signature {
    fn vca_try_from(x: CredentialBundle<S>) -> VCAResult<Signature> {
        Ok(Signature(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&Signature> for CredentialBundle<S> {
    fn vca_try_from(x: &Signature) -> VCAResult<CredentialBundle<S>> {
        from_opaque_json(&x.0)
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<BlindCredentialRequest<S>> for BlindInfoForSigner {
    fn vca_try_from(x: BlindCredentialRequest<S>) -> VCAResult<BlindInfoForSigner> {
        Ok(BlindInfoForSigner(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&BlindInfoForSigner> for BlindCredentialRequest<S> {
    fn vca_try_from(x: &BlindInfoForSigner) -> VCAResult<BlindCredentialRequest<S>> {
        from_opaque_json(&x.0)
    }
}

impl VcaTryFrom<Scalar> for InfoForUnblinding {
    fn vca_try_from(x: Scalar) -> VCAResult<InfoForUnblinding> {
        Ok(InfoForUnblinding(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&InfoForUnblinding> for Scalar {
    fn vca_try_from(x: &InfoForUnblinding) -> VCAResult<Scalar> {
        from_opaque_json(&x.0)
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<BlindCredentialBundle<S>> for BlindSignature {
    fn vca_try_from(x: BlindCredentialBundle<S>) -> VCAResult<BlindSignature> {
        Ok(BlindSignature(to_opaque_json(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&BlindSignature> for BlindCredentialBundle<S> {
    fn vca_try_from(x: &BlindSignature) -> VCAResult<BlindCredentialBundle<S>> {
        from_opaque_json(&x.0)
    }
}

