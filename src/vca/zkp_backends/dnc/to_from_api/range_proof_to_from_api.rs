// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::vca::interfaces::types as api;
// ------------------------------------------------------------------------------
use legogroth16;
// ------------------------------------------------------------------------------
use ark_bls12_381::Bls12_381;
// ------------------------------------------------------------------------------

impl VcaTryFrom<legogroth16::ProvingKey<Bls12_381>> for api::RangeProofProvingKey {
    fn vca_try_from(x: legogroth16::ProvingKey<Bls12_381>) -> VCAResult<api::RangeProofProvingKey> {
        Ok(api::RangeProofProvingKey(to_opaque_ark(&x)?))
    }
}

impl VcaTryFrom<&api::RangeProofProvingKey> for legogroth16::ProvingKey<Bls12_381> {
    fn vca_try_from(x: &api::RangeProofProvingKey) -> VCAResult<legogroth16::ProvingKey<Bls12_381>> {
        from_opaque_ark(&x.0)
    }
}

