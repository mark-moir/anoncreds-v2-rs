// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::vca::interfaces::crypto_interface::*;
use crate::vca::interfaces::types as api;
// ------------------------------------------------------------------------------
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use proof_system::prelude::Proof;
use saver::prelude::*;
use vb_accumulator::prelude::MembershipWitness;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// ------------------------------------------------------------------------------
use serde::*;
use std::collections::HashMap;
// ------------------------------------------------------------------------------

pub type AccumWitnesses     = HashMap<api::CredAttrIndex, MembershipWitness::<G1>>;
pub type DecryptionLookups  =
    HashMap<(CredentialLabel, CredAttrIndex, SharedParamKey),
            (StmtIndex, AuthorityPublicSetupData)>;
pub type G1                 = <Bls12_381 as Pairing>::G1Affine;
pub type ImplSignature      = SignatureG1::<Bls12_381>;
pub type ProofG1            = Proof<Bls12_381>;
pub type SecretKeyBls12_381 = SecretKey<<Bls12_381 as Pairing>::ScalarField>;
pub type StmtIndex          = usize;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AuthorityPublicSetupData {
    pub chunk_bit_size    : u8,
    pub chunked_comm_gens : ChunkedCommitmentGens::<G1>,
    pub enc_gens          : EncryptionGens::<Bls12_381>,
    pub encryption_key    : EncryptionKey::<Bls12_381>,
    pub snark_proving_key : saver::saver_groth16::ProvingKey::<Bls12_381>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct BlindInfoCorrectnessProof {
    pub u_tilde: G1Affine,
    pub v_dash_cap: Fr,
    pub m_caps: Vec<(usize, Fr)>,
}

#[derive(CanonicalSerialize, CanonicalDeserialize, Clone, Debug)]
pub struct BlindInfoForSignerPayload {
    pub blinding_info: G1Affine,
    pub blinding_info_correctness_proof: BlindInfoCorrectnessProof,
}

// ------------------------------------------------------------------------------
