// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::{impl_vca_roundtrip_json, impl_vca_roundtrip_ark};
use crate::vca::interfaces::types as api;
use crate::vca::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use saver::keygen::DecryptionKey as SaverDecryptionKey;
use saver::keygen::SecretKey     as SaverSecretKey;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381,Fr};
// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(AuthorityPublicSetupData => api::AuthorityPublicData);

// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(SaverSecretKey::<Fr> => api::AuthoritySecretData);

// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(SaverDecryptionKey::<Bls12_381> => api::AuthorityDecryptionKey);

// ------------------------------------------------------------------------------

impl_vca_roundtrip_ark!((Fr, G1) => api::DecryptionProof);
