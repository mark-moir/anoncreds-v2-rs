// ------------------------------------------------------------------------------
use crate::vca::VCAResult;
use crate::vca::r#impl::to_from_api::*;
use crate::vca::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::blsful::inner_types::G1Projective;
// ------------------------------------------------------------------------------
use serde::*;
// ------------------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RangeProofCommitmentSetup {
    pub message_generator : G1Projective,
    pub blinder_generator : G1Projective,
}

impl VcaTryFrom<&RangeProofCommitmentSetup> for RangeProofProvingKey {
    fn vca_try_from(x: &RangeProofCommitmentSetup) -> VCAResult<RangeProofProvingKey> {
        Ok(RangeProofProvingKey(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&RangeProofProvingKey> for RangeProofCommitmentSetup {
    fn vca_try_from(x: &RangeProofProvingKey) -> VCAResult<RangeProofCommitmentSetup> {
        from_opaque_json(&x.0)
    }
}

