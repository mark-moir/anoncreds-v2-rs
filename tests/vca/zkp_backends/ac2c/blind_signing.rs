use blsful::inner_types::Scalar as BlsScalar;
use credx::blind::BlindCredentialRequest;
use credx::knox::bbs::BbsScheme;
use credx::knox::ps::PsScheme;
use credx::vca::r#impl::to_from_api::{from_api, to_api};
use credx::vca::Error;
use credx::vca::types as api;
use credx::vca::zkp_backends::ac2c::crypto_interface::{
    CRYPTO_INTERFACE_AC2C_BBS, CRYPTO_INTERFACE_AC2C_PS,
};
use crate::{
    blind_signing_happy_path, blind_signing_nonce_mismatch, gen_blind_signing_tests,
};

// General tests (happy path + nonce mismatch) for each CRYPTO_INTERFACE

blind_signing_happy_path!(blind_sign_roundtrip_ok_bbs, &CRYPTO_INTERFACE_AC2C_BBS);
blind_signing_happy_path!(blind_sign_roundtrip_ok_ps, &CRYPTO_INTERFACE_AC2C_PS);

// TODO: AC2C backend currently relies on the built-in proof and verification, but it doesn't receive the nonce
// Therefore these tests are ignored.
blind_signing_nonce_mismatch!(blind_sign_nonce_mismatch_bbs, &CRYPTO_INTERFACE_AC2C_BBS, ignore);
blind_signing_nonce_mismatch!(blind_sign_nonce_mismatch_ps, &CRYPTO_INTERFACE_AC2C_PS, ignore);

fn ac2c_tamper_commitment<
    S: Clone + credx::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme,
>(
    mut good: api::BlindSigningInfo,
    alt: api::BlindSigningInfo,
) -> api::BlindSigningInfo {
    let mut req_good: BlindCredentialRequest<S> = from_api(&good.blind_info_for_signer).expect("convert good");
    let req_alt: BlindCredentialRequest<S> = from_api(&alt.blind_info_for_signer).expect("convert alt");
    req_good.blind_signature_context = req_alt.blind_signature_context;
    good.blind_info_for_signer = to_api(req_good).expect("encode tampered");
    good
}

fn ac2c_tamper_commitment_bbs(
    good: api::BlindSigningInfo,
    alt: api::BlindSigningInfo,
) -> api::BlindSigningInfo {
    ac2c_tamper_commitment::<BbsScheme>(good, alt)
}

fn ac2c_tamper_commitment_ps(
    good: api::BlindSigningInfo,
    alt: api::BlindSigningInfo,
) -> api::BlindSigningInfo {
    ac2c_tamper_commitment::<PsScheme>(good, alt)
}

fn ac2c_tamper_proof_bbs(
    mut good: api::BlindSigningInfo,
    _alt: api::BlindSigningInfo,
) -> api::BlindSigningInfo {
    let mut req_good: BlindCredentialRequest<BbsScheme> = from_api(&good.blind_info_for_signer).expect("convert good");
    let p = req_good
        .blind_signature_context
        .proofs
        .get_mut(0)
        .expect("expected at least one proof scalar");
    *p = BlsScalar::from_okm(&[1u8; 48]);
    good.blind_info_for_signer = to_api(req_good).expect("encode tampered");
    good
}

fn ac2c_tamper_proof_ps(
    mut good: api::BlindSigningInfo,
    _alt: api::BlindSigningInfo,
) -> api::BlindSigningInfo {
    let mut req_good: BlindCredentialRequest<PsScheme> = from_api(&good.blind_info_for_signer).expect("convert good");
    let p = req_good
        .blind_signature_context
        .proofs
        .get_mut(0)
        .expect("expected at least one proof scalar");
    *p = BlsScalar::from_okm(&[2u8; 48]);
    good.blind_info_for_signer = to_api(req_good).expect("encode tampered");
    good
}

pub fn expect_invalid_signing(e: &Error) -> bool {
    format!("{e:?}").contains("InvalidSigningOperation")
}

gen_blind_signing_tests!(
    ac2c_bbs_tamper_commitment, &CRYPTO_INTERFACE_AC2C_BBS, api::BlindSigningInfo, ac2c_tamper_commitment_bbs, crate::vca::zkp_functionality_tests::blind_signing_common::from_api_identity, crate::vca::zkp_functionality_tests::blind_signing_common::to_api_identity, Some(expect_invalid_signing);
    ac2c_bbs_tamper_proof,      &CRYPTO_INTERFACE_AC2C_BBS, api::BlindSigningInfo, ac2c_tamper_proof_bbs,      crate::vca::zkp_functionality_tests::blind_signing_common::from_api_identity, crate::vca::zkp_functionality_tests::blind_signing_common::to_api_identity, Some(expect_invalid_signing);
    ac2c_ps_tamper_commitment,  &CRYPTO_INTERFACE_AC2C_PS,  api::BlindSigningInfo, ac2c_tamper_commitment_ps,  crate::vca::zkp_functionality_tests::blind_signing_common::from_api_identity, crate::vca::zkp_functionality_tests::blind_signing_common::to_api_identity, Some(expect_invalid_signing);
    ac2c_ps_tamper_proof,       &CRYPTO_INTERFACE_AC2C_PS,  api::BlindSigningInfo, ac2c_tamper_proof_ps,       crate::vca::zkp_functionality_tests::blind_signing_common::from_api_identity, crate::vca::zkp_functionality_tests::blind_signing_common::to_api_identity, Some(expect_invalid_signing);
);
