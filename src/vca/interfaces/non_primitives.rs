//! See the module comment for [`crate::vca::interfaces::primitives`].
// ---------------------------------------------------------------------------
use crate::vca::VCAResult;
use crate::vca::types::*;
// ---------------------------------------------------------------------------
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;
// ---------------------------------------------------------------------------

pub type CreateSignerData = Arc<
    dyn Fn(
        Natural, // RNG seed
        &[ClaimType],
        &[CredAttrIndex],
        ProofMode
        ) -> VCAResult<SignerData>
        + Send
        + Sync,
>;

pub type CreateBlindSigningInfo = Arc<
    dyn Fn(
        Natural, // RNG seed
        &SignerPublicData,
        &[CredAttrIndexAndDataValue],  // Blinded attributes
        ProofMode
    ) -> VCAResult<BlindSigningInfo>
    + Send
    + Sync,
>;

pub type Sign = Arc<
    dyn Fn(
        Natural, // RNG seed
        &[DataValue],
        &SignerData,
        ProofMode
    ) -> VCAResult<Signature>
    + Send
    + Sync,
>;

pub type SignWithBlindedAttributes = Arc<
    dyn Fn(
        Natural, // RNG seed
        &[CredAttrIndexAndDataValue],  // Non-blinded attributes
        &BlindInfoForSigner,
        &SignerData,
        ProofMode
    ) -> VCAResult<BlindSignature>
    + Send
    + Sync,
>;

pub type UnblindBlindedSignature = Arc<
    dyn Fn(
        &[ClaimType],
        &[CredAttrIndexAndDataValue],  // Blinded attributes, same as used for CreateBlindSigningInfo
        &BlindSignature,
        &InfoForUnblinding,
        ProofMode
    ) -> VCAResult<Signature>
    + Send
    + Sync,
>;

pub type CreateProof = Arc<
    dyn Fn(
            &HashMap<CredentialLabel, CredentialReqs>,
            &HashMap<SharedParamKey, SharedParamValue>,
            &HashMap<CredentialLabel, SignatureAndRelatedData>,
            ProofMode,
            Option<Nonce>,
        ) -> VCAResult<WarningsAndDataForVerifier>
        + Send
        + Sync,
>;

pub type VerifyProof = Arc<
    dyn Fn(
            &HashMap<CredentialLabel, CredentialReqs>,
            &HashMap<SharedParamKey, SharedParamValue>,
            &DataForVerifier,
            &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptRequest>>>,
            ProofMode,
            Option<Nonce>,
        ) -> VCAResult<WarningsAndDecryptResponses>
        + Send
        + Sync,
>;

pub type VerifyDecryption = Arc<
    dyn Fn(
            &HashMap<CredentialLabel, CredentialReqs>,
            &HashMap<SharedParamKey, SharedParamValue>,
            &DataForVerifier,
            &HashMap<SharedParamKey, AuthorityDecryptionKey>,
            &HashMap<CredentialLabel, HashMap<CredAttrIndex, HashMap<AuthorityLabel, DecryptResponse>>>,
            ProofMode,
            Option<Nonce>,
        ) -> VCAResult<Vec<Warning>>
        + Send
        + Sync,
>;

