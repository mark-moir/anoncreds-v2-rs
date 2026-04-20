// ------------------------------------------------------------------------------
use crate::vca::VCAResult;
use crate::vca::r#impl::to_from_api::*;
use crate::{impl_vca_roundtrip_json, impl_vca_roundtrip_ark};
use crate::vca::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
// ------------------------------------------------------------------------------
use serde::*;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(vb20::SecretKey => AccumulatorSecretData);

impl VcaTryFrom<&str> for vb20::SecretKey {
    fn vca_try_from(s: &str) -> VCAResult<vb20::SecretKey> {
        from_opaque_json(s)
    }
}

// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(vb20::PublicKey => AccumulatorPublicData);

// ------------------------------------------------------------------------------

impl VcaTryFrom<(vb20::SecretKey, vb20::PublicKey)> for AccumulatorData {
    fn vca_try_from((sk, pk) : (vb20::SecretKey, vb20::PublicKey)
    ) -> VCAResult<AccumulatorData> {
        Ok(AccumulatorData {
            accumulator_public_data : AccumulatorPublicData(to_opaque_json(&pk)?),
            accumulator_secret_data : AccumulatorSecretData(to_opaque_json(&sk)?),
        })
    }
}

impl VcaTryFrom<&AccumulatorData> for (vb20::SecretKey, vb20::PublicKey) {
    fn vca_try_from(x: &AccumulatorData) -> VCAResult<(vb20::SecretKey, vb20::PublicKey)> {
        let AccumulatorData { accumulator_secret_data, accumulator_public_data } = x;
        let sk                                           = from_opaque_json(&accumulator_secret_data.0)?;
        let pk                                           = from_opaque_json(&accumulator_public_data.0)?;
        Ok((sk, pk))
    }
}

// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(vb20::Accumulator => Accumulator);

// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(vb20::Element => AccumulatorElement);

// ------------------------------------------------------------------------------

impl_vca_roundtrip_json!(vb20::MembershipWitness => AccumulatorMembershipWitness);

// ------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AC2CWitnessUpdateInfo {
    pub ac2c_adds         : Vec<AccumulatorElement>,
    pub ac2c_rms          : Vec<AccumulatorElement>,
    pub ac2c_coefficients : Vec<Coefficient>,
}


impl VcaTryFrom<AC2CWitnessUpdateInfo> for AccumulatorWitnessUpdateInfo {
    fn vca_try_from(x : AC2CWitnessUpdateInfo) -> VCAResult<AccumulatorWitnessUpdateInfo> {
        Ok(AccumulatorWitnessUpdateInfo(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&AccumulatorWitnessUpdateInfo> for AC2CWitnessUpdateInfo {
    fn vca_try_from(x: &AccumulatorWitnessUpdateInfo) -> VCAResult<AC2CWitnessUpdateInfo> {
        from_opaque_json(&x.0)
    }
}
