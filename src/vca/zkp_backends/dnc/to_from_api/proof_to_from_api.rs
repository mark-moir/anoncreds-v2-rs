// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::vca::interfaces::types as api;
use crate::vca::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------

impl VcaTryFrom<ProofG1> for api::Proof {
    fn vca_try_from(x: ProofG1) -> VCAResult<api::Proof> {
        Ok(api::Proof(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::Proof> for ProofG1 {
    fn vca_try_from(x: &api::Proof) -> VCAResult<ProofG1> {
        from_opaque_json(&x.0)
    }
}

