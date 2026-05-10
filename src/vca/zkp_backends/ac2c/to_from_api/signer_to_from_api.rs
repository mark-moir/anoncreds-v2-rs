use crate::blind::BlindCredentialRequest;
// ------------------------------------------------------------------------------
use crate::impl_vca_roundtrip_json;
use crate::vca::r#impl::to_from_api::*;
use crate::vca::types::*;
use crate::vca::VCAResult;
use crate::vca::zkp_backends::ac2c::signer::AC2C_DOES_NOT_SURFACE_BSICP;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::blsful::inner_types::*;
use crate::prelude::blsful::{Bls12381G2Impl, SecretKey};
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
use crate::prelude::{BlindCredentialBundle, CredentialBundle, Issuer, IssuerPublic};
use serde::{Deserialize, Serialize};
// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(Scalar => InfoForUnblinding);

// ------------------------------------------------------------------------------

// Explicit impls below as our macros can't handle parameterised types

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ac2cSignerPublicSetupDataCorrectnessProof(pub OpaqueMaterial);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "IssuerPublic<S>: Serialize",
    deserialize = "IssuerPublic<S>: Deserialize<'de>"
))]
pub struct Ac2cSignerPublicSetupDataWithProof<S: ShortGroupSignatureScheme> {
    pub issuer_public: IssuerPublic<S>,
    pub correctness_proof: Ac2cSignerPublicSetupDataCorrectnessProof,
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<Ac2cSignerPublicSetupDataWithProof<S>>
    for SignerPublicSetupData
{
    fn vca_try_from(x: Ac2cSignerPublicSetupDataWithProof<S>) -> VCAResult<SignerPublicSetupData> {
        Ok(SignerPublicSetupData {
            signer_public_setup_data: to_opaque_json(&x.issuer_public)?,
            signer_public_setup_data_correctness_proof: SignerPublicSetupDataCorrectnessProof(
                x.correctness_proof.0,
            ),
        })
    }
}
impl<S: ShortGroupSignatureScheme> VcaTryFrom<&SignerPublicSetupData>
    for Ac2cSignerPublicSetupDataWithProof<S>
{
    fn vca_try_from(x: &SignerPublicSetupData) -> VCAResult<Ac2cSignerPublicSetupDataWithProof<S>> {
        Ok(Ac2cSignerPublicSetupDataWithProof {
            issuer_public: from_opaque_json(&x.signer_public_setup_data)?,
            correctness_proof: Ac2cSignerPublicSetupDataCorrectnessProof(
                x.signer_public_setup_data_correctness_proof.0.clone(),
            ),
        })
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&SignerPublicSetupData> for IssuerPublic<S> {
    fn vca_try_from(x: &SignerPublicSetupData) -> VCAResult<IssuerPublic<S>> {
        Ok(from_opaque_json(&x.signer_public_setup_data)?)
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ac2cSignatureCorrectnessProof(pub OpaqueMaterial);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "CredentialBundle<S>: Serialize",
    deserialize = "CredentialBundle<S>: Deserialize<'de>"
))]
pub struct Ac2cSignatureWithProof<S: ShortGroupSignatureScheme> {
    pub signature: CredentialBundle<S>,
    pub correctness_proof: Ac2cSignatureCorrectnessProof,
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<Ac2cSignatureWithProof<S>> for Signature {
    fn vca_try_from(x: Ac2cSignatureWithProof<S>) -> VCAResult<Signature> {
        Ok(Signature {
            signature: to_opaque_json(&x.signature)?,
            signature_correctness_proof: SignatureCorrectnessProof(x.correctness_proof.0),
        })
    }
}
impl<S: ShortGroupSignatureScheme> VcaTryFrom<&Signature> for Ac2cSignatureWithProof<S> {
    fn vca_try_from(x: &Signature) -> VCAResult<Ac2cSignatureWithProof<S>> {
        Ok(Ac2cSignatureWithProof {
            signature: from_opaque_json(&x.signature)?,
            correctness_proof: Ac2cSignatureCorrectnessProof(
                x.signature_correctness_proof.0.clone(),
            ),
        })
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&Signature> for CredentialBundle<S> {
    fn vca_try_from(x: &Signature) -> VCAResult<CredentialBundle<S>> {
        Ok(from_opaque_json(&x.signature)?)
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<BlindCredentialRequest<S>> for BlindInfoForSigner {
    fn vca_try_from(x: BlindCredentialRequest<S>) -> VCAResult<BlindInfoForSigner> {
        Ok(BlindInfoForSigner {
            blinding_info: to_opaque_json(&x)?,
            blind_signing_info_correctness_proof: BlindSigningInfoCorrectnessProof(
                AC2C_DOES_NOT_SURFACE_BSICP.to_string(),
            ),
        })
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&BlindInfoForSigner> for BlindCredentialRequest<S> {
    fn vca_try_from(x: &BlindInfoForSigner) -> VCAResult<BlindCredentialRequest<S>> {
        from_opaque_json(&x.blinding_info)
    }
}

// ------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ac2cBlindSignatureCorrectnessProof(pub OpaqueMaterial);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(bound(
    serialize = "BlindCredentialBundle<S>: Serialize",
    deserialize = "BlindCredentialBundle<S>: Deserialize<'de>"
))]
pub struct Ac2cBlindSignatureWithProof<S: ShortGroupSignatureScheme> {
    pub blind_signature: BlindCredentialBundle<S>,
    pub correctness_proof: Ac2cBlindSignatureCorrectnessProof,
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<Ac2cBlindSignatureWithProof<S>> for BlindSignature {
    fn vca_try_from(x: Ac2cBlindSignatureWithProof<S>) -> VCAResult<BlindSignature> {
        Ok(BlindSignature {
            blind_signature: to_opaque_json(&x.blind_signature)?,
            blind_signature_correctness_proof: BlindSignatureCorrectnessProof(
                x.correctness_proof.0,
            ),
        })
    }
}
impl<S: ShortGroupSignatureScheme> VcaTryFrom<&BlindSignature> for Ac2cBlindSignatureWithProof<S> {
    fn vca_try_from(x: &BlindSignature) -> VCAResult<Ac2cBlindSignatureWithProof<S>> {
        Ok(Ac2cBlindSignatureWithProof {
            blind_signature: from_opaque_json(&x.blind_signature)?,
            correctness_proof: Ac2cBlindSignatureCorrectnessProof(
                x.blind_signature_correctness_proof.0.clone(),
            ),
        })
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&BlindSignature> for BlindCredentialBundle<S> {
    fn vca_try_from(x: &BlindSignature) -> VCAResult<BlindCredentialBundle<S>> {
        Ok(from_opaque_json(&x.blind_signature)?)
    }
}
