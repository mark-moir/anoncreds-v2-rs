// ------------------------------------------------------------------------------
use crate::vca::VCAResult;
use crate::vca::r#impl::to_from_api::*;
use crate::vca::types::*;
// ------------------------------------------------------------------------------
use crate::prelude::vb20;
use crate::prelude::vb20::Coefficient;
// ------------------------------------------------------------------------------
use serde::*;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

impl VcaTryFrom<vb20::SecretKey> for AccumulatorSecretData {
    fn vca_try_from(x: vb20::SecretKey) -> VCAResult<AccumulatorSecretData> {
        Ok(AccumulatorSecretData(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&AccumulatorSecretData> for vb20::SecretKey {
    fn vca_try_from(x: &AccumulatorSecretData) -> VCAResult<vb20::SecretKey> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<&vb20::SecretKey> for AccumulatorSecretData {
    fn vca_try_from(x: &vb20::SecretKey) -> VCAResult<AccumulatorSecretData> {
        Ok(AccumulatorSecretData(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&str> for vb20::SecretKey {
    fn vca_try_from(s: &str) -> VCAResult<vb20::SecretKey> {
        from_opaque_json(s)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<vb20::PublicKey> for AccumulatorPublicData {
    fn vca_try_from(x: vb20::PublicKey) -> VCAResult<AccumulatorPublicData> {
        Ok(AccumulatorPublicData(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&AccumulatorPublicData> for vb20::PublicKey {
    fn vca_try_from(x: &AccumulatorPublicData) -> VCAResult<vb20::PublicKey> {
        from_opaque_json(&x.0)
    }
}

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

impl VcaTryFrom<vb20::Accumulator> for Accumulator {
    fn vca_try_from(x: vb20::Accumulator) -> VCAResult<Accumulator> {
        Ok(Accumulator(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&Accumulator> for vb20::Accumulator {
    fn vca_try_from(x: &Accumulator) -> VCAResult<vb20::Accumulator> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<vb20::Element> for AccumulatorElement {
    fn vca_try_from(x : vb20::Element) -> VCAResult<AccumulatorElement> {
        Ok(AccumulatorElement(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&AccumulatorElement> for vb20::Element {
    fn vca_try_from(x: &AccumulatorElement) -> VCAResult<vb20::Element> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<vb20::MembershipWitness> for AccumulatorMembershipWitness {
    fn vca_try_from(x : vb20::MembershipWitness) -> VCAResult<AccumulatorMembershipWitness> {
        Ok(AccumulatorMembershipWitness(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&AccumulatorMembershipWitness> for vb20::MembershipWitness {
    fn vca_try_from(x: &AccumulatorMembershipWitness) -> VCAResult<vb20::MembershipWitness> {
        from_opaque_json(&x.0)
    }
}

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
