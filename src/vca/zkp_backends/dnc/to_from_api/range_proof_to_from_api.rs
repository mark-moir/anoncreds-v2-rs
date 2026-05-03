// ------------------------------------------------------------------------------
use crate::impl_vca_roundtrip_ark;
use crate::vca::interfaces::types as api;
use crate::vca::r#impl::to_from_api::*;
use crate::vca::{Error, VCAResult};
// ------------------------------------------------------------------------------
use legogroth16;
// ------------------------------------------------------------------------------
use ark_bls12_381::Bls12_381;
// ------------------------------------------------------------------------------

impl_vca_roundtrip_ark!(legogroth16::ProvingKey<Bls12_381> => api::RangeProofProvingKey);
