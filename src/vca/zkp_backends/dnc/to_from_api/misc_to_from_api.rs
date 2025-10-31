// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::vca::interfaces::types as api;
use crate::vca::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------

impl VcaTryFrom<(ImplSignature, Vec<api::DataValue>, AccumWitnesses)> for api::SignatureAndRelatedData {
    fn vca_try_from((s,values,w) : (ImplSignature, Vec<api::DataValue>, AccumWitnesses)) -> VCAResult<api::SignatureAndRelatedData> {
        let signature             = to_api(s)?;
        let accumulator_witnesses = to_api(w)?;
        Ok(api::SignatureAndRelatedData {signature, values, accumulator_witnesses})
    }
}

impl VcaTryFrom<&api::SignatureAndRelatedData> for (ImplSignature, Vec<api::DataValue>, AccumWitnesses) {
    fn vca_try_from(x: &api::SignatureAndRelatedData) -> VCAResult<(ImplSignature, Vec<api::DataValue>, AccumWitnesses)> {
        let api::SignatureAndRelatedData { signature, values, accumulator_witnesses } = x;
        Ok((from_api(signature)?, values.to_vec(), from_api(accumulator_witnesses)?))
    }
}

