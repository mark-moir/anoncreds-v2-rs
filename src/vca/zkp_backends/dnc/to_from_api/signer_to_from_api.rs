// ------------------------------------------------------------------------------
use crate::vca::interfaces::types as api;
use crate::vca::r#impl::to_from_api::*;
use crate::vca::zkp_backends::dnc::types::*;
use crate::vca::{Error, VCAResult};
use crate::{impl_vca_roundtrip_ark, impl_vca_roundtrip_json};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
// ------------------------------------------------------------------------------
use bbs_plus::prelude::KeypairG2;
use bbs_plus::prelude::PublicKeyG2;
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use bbs_plus::prelude::SignatureParamsG1;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DncSignerPublicSetupDataCorrectnessProof(pub Vec<u8>);

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DncSignerPublicSetupData {
    pub sig_params: SignatureParamsG1<Bls12_381>,
    pub pk: PublicKeyG2<Bls12_381>,
    pub correctness_proof: DncSignerPublicSetupDataCorrectnessProof,
}

impl VcaTryFrom<DncSignerPublicSetupData> for api::SignerPublicSetupData {
    fn vca_try_from(d: DncSignerPublicSetupData) -> VCAResult<api::SignerPublicSetupData> {
        Ok(api::SignerPublicSetupData {
            signer_public_setup_data: to_opaque_ark(&(d.sig_params, d.pk))?,
            signer_public_setup_data_correctness_proof: api::SignerPublicSetupDataCorrectnessProof(
                to_opaque_ark(&d.correctness_proof)?,
            ),
        })
    }
}

impl VcaTryFrom<&api::SignerPublicSetupData> for DncSignerPublicSetupData {
    fn vca_try_from(x: &api::SignerPublicSetupData) -> VCAResult<DncSignerPublicSetupData> {
        let (sig_params, pk): (SignatureParamsG1<Bls12_381>, PublicKeyG2<Bls12_381>) =
            from_opaque_ark(&x.signer_public_setup_data)?;
        let correctness_proof: DncSignerPublicSetupDataCorrectnessProof =
            from_opaque_ark(&x.signer_public_setup_data_correctness_proof.0)?;
        Ok(DncSignerPublicSetupData {
            sig_params,
            pk,
            correctness_proof,
        })
    }
}

impl VcaTryFrom<&api::SignerPublicSetupData>
    for (SignatureParamsG1<Bls12_381>, PublicKeyG2<Bls12_381>)
{
    fn vca_try_from(
        x: &api::SignerPublicSetupData,
    ) -> VCAResult<(SignatureParamsG1<Bls12_381>, PublicKeyG2<Bls12_381>)> {
        let (sig_params, pk): (SignatureParamsG1<Bls12_381>, PublicKeyG2<Bls12_381>) =
            from_opaque_ark(&x.signer_public_setup_data)?;
        Ok((sig_params, pk))
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DncSignatureCorrectnessProof(pub api::OpaqueMaterial);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DncSignatureWithProof {
    pub signature: SignatureG1<Bls12_381>,
    pub correctness_proof: DncSignatureCorrectnessProof,
}

impl VcaTryFrom<DncSignatureWithProof> for api::Signature {
    fn vca_try_from(x: DncSignatureWithProof) -> VCAResult<api::Signature> {
        Ok(api::Signature {
            signature: to_opaque_ark(&x.signature)?,
            signature_correctness_proof: api::SignatureCorrectnessProof(x.correctness_proof.0),
        })
    }
}

impl VcaTryFrom<&api::Signature> for DncSignatureWithProof {
    fn vca_try_from(x: &api::Signature) -> VCAResult<DncSignatureWithProof> {
        Ok(DncSignatureWithProof {
            signature: from_opaque_ark(&x.signature)?,
            correctness_proof: DncSignatureCorrectnessProof(
                x.signature_correctness_proof.0.clone(),
            ),
        })
    }
}

impl VcaTryFrom<&api::Signature> for SignatureG1<Bls12_381> {
    fn vca_try_from(x: &api::Signature) -> VCAResult<SignatureG1<Bls12_381>> {
        Ok(from_opaque_ark(&x.signature)?)
    }
}

// ---------------------------------------------------------------------------
// Blind info for signer (commitment + correctness proof) to/from API

impl VcaTryFrom<DncBlindInfoForSigner> for api::BlindInfoForSigner {
    fn vca_try_from(x: DncBlindInfoForSigner) -> VCAResult<api::BlindInfoForSigner> {
        Ok(api::BlindInfoForSigner {
            blinding_info: to_opaque_ark(&x.blinding_info)?,
            blind_signing_info_correctness_proof: to_api(x.blinding_info_correctness_proof)?,
        })
    }
}

impl VcaTryFrom<&api::BlindInfoForSigner> for DncBlindInfoForSigner {
    fn vca_try_from(x: &api::BlindInfoForSigner) -> VCAResult<DncBlindInfoForSigner> {
        Ok(DncBlindInfoForSigner {
            blinding_info: from_opaque_ark(&x.blinding_info)?,
            blinding_info_correctness_proof: from_api(&x.blind_signing_info_correctness_proof)?,
        })
    }
}

// ------------------------------------------------------------------------------

impl_vca_roundtrip_ark!(Fr => api::InfoForUnblinding);

// ------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DncBlindSignatureCorrectnessProof(pub api::OpaqueMaterial);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DncBlindSignatureWithProof {
    pub blind_signature: SignatureG1<Bls12_381>,
    pub correctness_proof: DncBlindSignatureCorrectnessProof,
}

impl VcaTryFrom<DncBlindSignatureWithProof> for api::BlindSignature {
    fn vca_try_from(x: DncBlindSignatureWithProof) -> VCAResult<api::BlindSignature> {
        Ok(api::BlindSignature {
            blind_signature: to_opaque_ark(&x.blind_signature)?,
            blind_signature_correctness_proof: api::BlindSignatureCorrectnessProof(
                x.correctness_proof.0,
            ),
        })
    }
}

impl VcaTryFrom<&api::BlindSignature> for DncBlindSignatureWithProof {
    fn vca_try_from(x: &api::BlindSignature) -> VCAResult<DncBlindSignatureWithProof> {
        Ok(DncBlindSignatureWithProof {
            blind_signature: from_opaque_ark(&x.blind_signature)?,
            correctness_proof: DncBlindSignatureCorrectnessProof(
                x.blind_signature_correctness_proof.0.clone(),
            ),
        })
    }
}

impl VcaTryFrom<&api::BlindSignature> for SignatureG1<Bls12_381> {
    fn vca_try_from(x: &api::BlindSignature) -> VCAResult<SignatureG1<Bls12_381>> {
        Ok(from_opaque_ark(&x.blind_signature)?)
    }
}

// ---------------------------------------------------------------------------
// Blind signing info correctness proof (proof_system proof) to/from API

impl VcaTryFrom<BlindInfoCorrectnessProof> for api::BlindSigningInfoCorrectnessProof {
    fn vca_try_from(
        x: BlindInfoCorrectnessProof,
    ) -> VCAResult<api::BlindSigningInfoCorrectnessProof> {
        Ok(api::BlindSigningInfoCorrectnessProof(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::BlindSigningInfoCorrectnessProof> for BlindInfoCorrectnessProof {
    fn vca_try_from(
        x: &api::BlindSigningInfoCorrectnessProof,
    ) -> VCAResult<BlindInfoCorrectnessProof> {
        from_opaque_json(&x.0)
    }
}
