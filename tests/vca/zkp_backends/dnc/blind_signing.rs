use ark_bls12_381::Fr;
use credx::vca::r#impl::to_from_api::{from_api, to_api};
use credx::vca::types as api;
use credx::vca::zkp_backends::dnc::crypto_interface::CRYPTO_INTERFACE_DNC;
use credx::vca::zkp_backends::dnc::types::{BlindInfoCorrectnessProof, DncBlindInfoForSigner};
use proof_system::statement_proof::StatementProof;

use crate::{
    blind_signing_happy_path, blind_signing_nonce_mismatch, gen_blind_signing_tests,
};
use credx::vca::Error;

// General tests (happy path + nonce mismatch)
blind_signing_happy_path!(blind_sign_roundtrip_ok_dnc, &CRYPTO_INTERFACE_DNC);
blind_signing_nonce_mismatch!(blind_sign_nonce_mismatch_dnc, &CRYPTO_INTERFACE_DNC, run);

fn dnc_tamper_commitment(
    mut good: api::BlindSigningInfo,
    alt: api::BlindSigningInfo,
) -> api::BlindSigningInfo {
    let mut payload_good: DncBlindInfoForSigner = from_api(&good.blind_info_for_signer).expect("decode");
    let payload_alt: DncBlindInfoForSigner = from_api(&alt.blind_info_for_signer).expect("decode");
    payload_good.blinding_info = payload_alt.blinding_info;
    good.blind_info_for_signer = to_api(payload_good).expect("encode tampered commitment");
    good
}

fn dnc_tamper_proof(
    mut good: api::BlindSigningInfo,
    _alt: api::BlindSigningInfo,
) -> api::BlindSigningInfo {
    let mut payload: DncBlindInfoForSigner = from_api(&good.blind_info_for_signer).expect("decode");
    let mut proof: BlindInfoCorrectnessProof = payload.blinding_info_correctness_proof;
    if let Some(StatementProof::PedersenCommitment(p)) = proof.0.statement_proofs.get_mut(0) {
        let resp = p.response.0.get_mut(0).expect("response present");
        *resp += Fr::from(3u128);
    }
    payload.blinding_info_correctness_proof = proof;
    good.blind_info_for_signer = to_api(payload).expect("encode proof tampered");
    good
}

pub fn expect_blind_info_failure(e: &Error) -> bool {
    let msg = format!("{e:?}");
    msg.contains("blind signing info correctness proof verification failed")
        || msg.contains("verify_blind_info_correctness_proof")
}

gen_blind_signing_tests!(
    dnc_tamper_commitment, &CRYPTO_INTERFACE_DNC, api::BlindSigningInfo, dnc_tamper_commitment, crate::vca::zkp_functionality_tests::blind_signing_common::from_api_identity, crate::vca::zkp_functionality_tests::blind_signing_common::to_api_identity, Some(expect_blind_info_failure);
    dnc_tamper_proof,       &CRYPTO_INTERFACE_DNC, api::BlindSigningInfo, dnc_tamper_proof,       crate::vca::zkp_functionality_tests::blind_signing_common::from_api_identity, crate::vca::zkp_functionality_tests::blind_signing_common::to_api_identity, Some(expect_blind_info_failure);
);
