// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::vca::interfaces::types as api;
use crate::vca::zkp_backends::dnc::in_memory_state::test::*;
use crate::vca::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use vb_accumulator::prelude::Keypair              as VbaKeypair;
use vb_accumulator::prelude::MembershipProvingKey as VbaMembershipProvingKey;
use vb_accumulator::prelude::MembershipWitness;
use vb_accumulator::prelude::Omega;
use vb_accumulator::prelude::PositiveAccumulator;
use vb_accumulator::prelude::PublicKey            as VbaPublicKey;
use vb_accumulator::prelude::SetupParams          as VbaSetupParams;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381,Fr,G1Affine};
// ------------------------------------------------------------------------------
use serde::*;
use std::collections::{HashMap,HashSet};
// ------------------------------------------------------------------------------

type AccumWitnessesAPI  = HashMap<api::CredAttrIndex, api::AccumulatorMembershipWitness>;

// ------------------------------------------------------------------------------

impl VcaTryFrom<Fr> for api::AccumulatorElement {
    fn vca_try_from(x: Fr) -> VCAResult<api::AccumulatorElement> {
        Ok(api::AccumulatorElement(to_opaque_ark(&x)?))
    }
}

impl VcaTryFrom<&api::AccumulatorElement> for Fr {
    fn vca_try_from(x: &api::AccumulatorElement) -> VCAResult<Fr> {
        from_opaque_ark(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<Vec<Fr>> for Vec<String> {
    fn vca_try_from(x: Vec<Fr>) -> VCAResult<Vec<String>> {
        x.iter().map(to_opaque_ark).collect()
    }
}

impl VcaTryFrom<&Vec<String>> for Vec<Fr> {
    fn vca_try_from(x: &Vec<String>) -> VCAResult<Vec<Fr>> {
        x.iter().map(|s : &String| from_opaque_ark(s)).collect()
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<(Omega::<G1>, Vec<Fr>, Vec<Fr>)> for api::AccumulatorWitnessUpdateInfo {
    fn vca_try_from((o,a,r): (Omega::<G1>, Vec<Fr>, Vec<Fr>)) -> VCAResult<api::AccumulatorWitnessUpdateInfo> {
        let ap : Vec<String> = to_api(a)?;
        let rp : Vec<String> = to_api(r)?;
        Ok(api::AccumulatorWitnessUpdateInfo(to_opaque_json(&(o, ap, rp))?))
    }
}

impl VcaTryFrom<&api::AccumulatorWitnessUpdateInfo> for (Omega::<G1>, Vec<Fr>, Vec<Fr>) {
    fn vca_try_from(x: &api::AccumulatorWitnessUpdateInfo) -> VCAResult<(Omega::<G1>, Vec<Fr>, Vec<Fr>)> {
        let (o, ap, rp) : (Omega::<G1>, Vec<String>, Vec<String>) = from_opaque_json(&x.0)?;
        let a : Vec<Fr> = from_api(&ap)?;
        let r : Vec<Fr> = from_api(&rp)?;
        Ok( (o, a, r) )
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<VbaMembershipProvingKey::<G1>> for api::MembershipProvingKey {
    fn vca_try_from(x: VbaMembershipProvingKey::<G1>) -> VCAResult<api::MembershipProvingKey> {
        Ok(api::MembershipProvingKey(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::MembershipProvingKey> for VbaMembershipProvingKey::<G1> {
    fn vca_try_from(x: &api::MembershipProvingKey) -> VCAResult<VbaMembershipProvingKey::<G1>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

#[cfg(not(feature="in_memory_state"))]
impl VcaTryFrom<PositiveAccumulator::<G1Affine>> for api::Accumulator {
    fn vca_try_from(x: PositiveAccumulator::<G1Affine>) -> VCAResult<api::Accumulator> {
        Ok(api::Accumulator(to_opaque_json(&x)?))
    }
}

#[cfg(not(feature="in_memory_state"))]
impl VcaTryFrom<&api::Accumulator> for PositiveAccumulator::<G1Affine> {
    fn vca_try_from(x: &api::Accumulator) -> VCAResult<PositiveAccumulator::<G1Affine>> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<(&VbaSetupParams::<Bls12_381>,  &VbaPublicKey::<Bls12_381>)> for api::AccumulatorPublicData {
    fn vca_try_from(x: (&VbaSetupParams::<Bls12_381>,  &VbaPublicKey::<Bls12_381>)) -> VCAResult<api::AccumulatorPublicData> {
        Ok(api::AccumulatorPublicData(to_opaque_json(&x)?))
    }
}

impl VcaTryFrom<&api::AccumulatorPublicData> for (VbaSetupParams::<Bls12_381>,  VbaPublicKey::<Bls12_381>) {
    fn vca_try_from(x: &api::AccumulatorPublicData) -> VCAResult<(VbaSetupParams::<Bls12_381>,  VbaPublicKey::<Bls12_381>)> {
        from_opaque_json(&x.0)
    }
}

// ------------------------------------------------------------------------------

#[cfg(feature="in_memory_state")]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct AccumulatorOpaque {
    pub acc : PositiveAccumulator::<G1Affine>,
    pub ims : InMemoryStateOpaque,
}

#[cfg(not(feature="in_memory_state"))]
impl VcaTryFrom<&PositiveAccumulator::<G1Affine>> for api::Accumulator {
    fn vca_try_from(acc: &PositiveAccumulator::<G1Affine>) -> VCAResult<api::Accumulator> {
        Ok(api::Accumulator(to_opaque_json(&acc)?))
    }
}

#[cfg(feature="in_memory_state")]
impl VcaTryFrom<(&PositiveAccumulator::<G1Affine>,
                 &InMemoryState::<Fr>)> for api::Accumulator {
    fn vca_try_from((acc,ims): (&PositiveAccumulator::<G1Affine>,
                                &InMemoryState::<Fr>,)) -> VCAResult<api::Accumulator> {
        print_in_memory_state(ims);
        let ims : InMemoryStateOpaque = to_api(ims)?;
        Ok(api::Accumulator(to_opaque_json(&(acc, ims))?))
    }
}

#[cfg(feature="in_memory_state")]
impl VcaTryFrom<&api::Accumulator> for (PositiveAccumulator::<G1Affine>,
                                        InMemoryState::<Fr>) {
    fn vca_try_from(x: &api::Accumulator) -> VCAResult<(PositiveAccumulator::<G1Affine>,
                                                        InMemoryState::<Fr>)> {
        let AccumulatorOpaque { acc, ims } = from_opaque_json(&x.0)?;
        let ims = from_api(&ims)?;
        // TODO: feature gate
        print_in_memory_state(&ims);
        Ok((acc, ims))
    }
}

impl VcaTryFrom<&VbaKeypair::<Bls12_381>> for api::AccumulatorSecretData {
    fn vca_try_from(kp: &VbaKeypair::<Bls12_381>) -> VCAResult<api::AccumulatorSecretData> {
        Ok(api::AccumulatorSecretData(to_opaque_json(&kp)?))
    }
}

impl VcaTryFrom<&api::AccumulatorSecretData> for VbaKeypair::<Bls12_381> {
    fn vca_try_from(x: &api::AccumulatorSecretData) -> VCAResult<VbaKeypair::<Bls12_381>> {
        let kp = from_opaque_json(&x.0)?;
        Ok(kp)
    }
}

// ------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct InMemoryStateOpaque(pub api::OpaqueMaterial);

impl VcaTryFrom<&InMemoryState::<Fr>> for InMemoryStateOpaque {
    fn vca_try_from(state: &InMemoryState::<Fr>) -> VCAResult<InMemoryStateOpaque> {
        let mut v = vec![];
        for elem in state.db.iter() { v.push(*elem); }
        Ok(InMemoryStateOpaque(to_opaque_ark(&v)?))
    }
}

impl VcaTryFrom<&InMemoryStateOpaque> for InMemoryState::<Fr> {
    fn vca_try_from(x: &InMemoryStateOpaque) -> VCAResult<InMemoryState::<Fr>> {
        let v : Vec<Fr> = from_opaque_ark(&x.0)?;
        let mut db      = HashSet::<Fr>::new();
        for e in v { db.insert(e); }
        let mut ims     = InMemoryState::<Fr>::new();
        ims.db          = db;
        Ok(ims)
    }
}

// ------------------------------------------------------------------------------

pub fn to_api_accumulator_data(
    sp  : &VbaSetupParams::<Bls12_381>,
    kp  : &VbaKeypair::<Bls12_381>,
) -> VCAResult<api::AccumulatorData>
{
    let ad = api::AccumulatorData {
        accumulator_public_data : to_api((sp, &kp.public_key))?,
        accumulator_secret_data : to_api(kp)?
    };
    Ok(ad)
}

#[allow(clippy::type_complexity)]
pub fn from_api_accumulator_data(
    ad : &api::AccumulatorData
) -> VCAResult<(VbaSetupParams::<Bls12_381>,
                VbaKeypair::<Bls12_381>)>
{
    let api::AccumulatorData { accumulator_public_data, accumulator_secret_data } = ad;
    let (sp, _pk)          = from_api(accumulator_public_data)?;
    let kp = from_api(accumulator_secret_data)?;
    Ok((sp, kp))
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<MembershipWitness::<G1>> for api::AccumulatorMembershipWitness {
    fn vca_try_from(x: MembershipWitness::<G1>) -> VCAResult<api::AccumulatorMembershipWitness> {
        Ok(api::AccumulatorMembershipWitness(to_opaque_ark(&x)?))
    }
}

impl VcaTryFrom<&api::AccumulatorMembershipWitness> for MembershipWitness::<G1> {
    fn vca_try_from(x: &api::AccumulatorMembershipWitness) -> VCAResult<MembershipWitness::<G1>> {
        from_opaque_ark(&x.0)
    }
}

// ------------------------------------------------------------------------------

impl VcaTryFrom<AccumWitnesses> for AccumWitnessesAPI {
    fn vca_try_from(x: AccumWitnesses) -> VCAResult<AccumWitnessesAPI> {
        let mut hm = HashMap::new();
        for (k,v) in x { hm.insert(k, to_api(v)?); }
        Ok(hm)
    }
}

impl VcaTryFrom<&AccumWitnessesAPI> for AccumWitnesses {
    fn vca_try_from(x: &AccumWitnessesAPI) -> VCAResult<AccumWitnesses> {
        let mut hm = HashMap::new();
        for (k,v) in x { hm.insert(*k, from_api(v)?); }
        Ok(hm)
    }
}
