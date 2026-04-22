use ark_bls12_381::G1Affine as DncBlindInfo;
use blsful::inner_types::Scalar as BlsScalar;
use credx::blind::BlindCredentialRequest;
use credx::knox::bbs::BbsScheme;
use credx::knox::ps::PsScheme;
use credx::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use credx::vca::api::VcaApi;
use credx::vca::api_utils::implement_vca_api_using;
use credx::vca::r#impl::to_from_api::{from_api, to_api};
use credx::vca::types as api;
use credx::vca::VCAResult;
use credx::vca::Error;
use ark_bls12_381::{G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use credx::vca::zkp_backends::ac2c::crypto_interface::{
    CRYPTO_INTERFACE_AC2C_BBS, CRYPTO_INTERFACE_AC2C_PS,
};
use credx::vca::zkp_backends::dnc::crypto_interface::CRYPTO_INTERFACE_DNC;


// Simple fixtures for a single-blinded attribute schema.
fn schema() -> Vec<api::ClaimType> {
    vec![
        api::ClaimType::CTText,
        api::ClaimType::CTInt,                 // blinded
        api::ClaimType::CTText,
        api::ClaimType::CTInt,
        api::ClaimType::CTAccumulatorMember,
    ]
}

fn blinded_idx() -> Vec<api::CredAttrIndex> {
    vec![1]
}

fn blinded_vals_good() -> Vec<api::CredAttrIndexAndDataValue> {
    vec![api::CredAttrIndexAndDataValue {
        index: 1,
        value: api::DataValue::DVInt(42),
    }]
}

fn blinded_vals_alt() -> Vec<api::CredAttrIndexAndDataValue> {
    vec![api::CredAttrIndexAndDataValue {
        index: 1,
        value: api::DataValue::DVInt(7),
    }]
}

fn non_blinded_vals() -> Vec<api::CredAttrIndexAndDataValue> {
    vec![
        (0, api::DataValue::DVText("meta".to_string())),
        (2, api::DataValue::DVText("ssn".to_string())),
        (3, api::DataValue::DVInt(180)),
        (4, api::DataValue::DVText("abcdef0123456789abcdef0123456789".to_string())),
    ]
    .into_iter()
    .map(|(i, v)| api::CredAttrIndexAndDataValue { index: i, value: v })
    .collect()
}

fn build_blind_infos(
    api: &VcaApi,
) -> VCAResult<(
    api::BlindSigningInfo,
    api::BlindSigningInfo,
    api::SignerData,
    Vec<api::CredAttrIndexAndDataValue>,
    Vec<api::ClaimType>,
)> {
    let create_signer_data = api.create_signer_data.clone();
    let create_blind_info = api.create_blind_signing_info.clone();

    let schema = schema();
    let blinded_idx = blinded_idx();
    let non_blinded = non_blinded_vals();

    let sd = create_signer_data(0, &schema, &blinded_idx, api::ProofMode::TestBackend)?;
    let bsi_good =
        create_blind_info(0, &sd.signer_public_data, &blinded_vals_good(), api::ProofMode::TestBackend)?;
    let bsi_alt =
        create_blind_info(0, &sd.signer_public_data, &blinded_vals_alt(), api::ProofMode::TestBackend)?;

    Ok((bsi_good, bsi_alt, sd, non_blinded, schema))
}

fn do_not_tamper<T>(g: T, _a: T) -> T { g }

fn alternative_tamper<T>(_g: T, a: T) -> T { a }

fn ac2c_tamper_commitment<S: Clone + ShortGroupSignatureScheme>(
    good: BlindCredentialRequest<S>,
    alt: BlindCredentialRequest<S>,
) -> BlindCredentialRequest<S> {
    let mut tampered = good;
    tampered.blind_signature_context = alt.blind_signature_context;
    tampered
}

fn ac2c_tamper_proof_bbs(
    mut good: BlindCredentialRequest<BbsScheme>,
    _alt: BlindCredentialRequest<BbsScheme>,
) -> BlindCredentialRequest<BbsScheme> {
    // Must actually alter proof data; fall back to alt if not enough proofs.
    let p = good
        .blind_signature_context
        .proofs
        .get_mut(0)
        .expect("expected at least one proof scalar");
    *p = BlsScalar::from_okm(&[1u8; 48]);
    good
}

fn ac2c_tamper_proof_ps(
    mut good: BlindCredentialRequest<PsScheme>,
    _alt: BlindCredentialRequest<PsScheme>,
) -> BlindCredentialRequest<PsScheme> {
    let p = good
        .blind_signature_context
        .proofs
        .get_mut(0)
        .expect("expected at least one proof scalar");
    *p = BlsScalar::from_okm(&[2u8; 48]);
    good
}

fn any_failure_will_do(_e: &Error) -> bool {
    true
}

fn dnc_tamper_proof(good: DncBlindInfo, _alt: DncBlindInfo) -> DncBlindInfo {
    let mut g1: G1Projective = good.into_group();
    g1 += G1Projective::generator();
    g1.into_affine()
}

fn expect_invalid_signing(e: &Error) -> bool {
    format!("{e:?}").contains("InvalidSigningOperation")
}

fn expect_blind_info_failure(e: &Error) -> bool {
    format!("{e:?}").contains("blind info proof verification failed")
}

fn run_blind_sign(
    api: VcaApi,
    bifs_builder: impl FnOnce(&api::BlindSigningInfo, &api::BlindSigningInfo) -> VCAResult<api::BlindInfoForSigner>,
) -> VCAResult<()> {
    let (bsi_good, bsi_alt, signer_data, non_blinded, schema) = build_blind_infos(&api)?;
    let blind_info_for_signer = bifs_builder(&bsi_good, &bsi_alt)?;

    let blinded_sig = (api.sign_with_blinded_attributes.clone())(
        0,
        &non_blinded,
        &blind_info_for_signer,
        &signer_data,
        api::ProofMode::TestBackend,
    )?;
    (api.unblind_blinded_signature.clone())(
        &schema,
        &bsi_good.blinded_attributes,
        &blinded_sig,
        &bsi_good.info_for_unblinding,
        api::ProofMode::TestBackend,
    )?;

    Ok(())
}

fn run_blind_sign_roundtrip<T: Clone>(
    api: VcaApi,
    tamper: impl Fn(T, T) -> T,
    from_api_fn: fn(&api::BlindInfoForSigner) -> VCAResult<T>,
    to_api_fn: fn(T) -> VCAResult<api::BlindInfoForSigner>,
) -> VCAResult<()> {
    run_blind_sign(api, |good, alt| {
        let payload_good = from_api_fn(&good.blind_info_for_signer)?;
        let payload_alt = from_api_fn(&alt.blind_info_for_signer)?;
        let payload_use = tamper(payload_good, payload_alt);
        to_api_fn(payload_use)
    })
}

fn from_api_ac2c_bbs(
    bi: &api::BlindInfoForSigner,
) -> VCAResult<BlindCredentialRequest<BbsScheme>> {
    from_api(bi)
}
fn to_api_ac2c_bbs(
    payload: BlindCredentialRequest<BbsScheme>,
) -> VCAResult<api::BlindInfoForSigner> {
    to_api(payload)
}

fn from_api_ac2c_ps(
    bi: &api::BlindInfoForSigner,
) -> VCAResult<BlindCredentialRequest<PsScheme>> {
    from_api(bi)
}
fn to_api_ac2c_ps(
    payload: BlindCredentialRequest<PsScheme>,
) -> VCAResult<api::BlindInfoForSigner> {
    to_api(payload)
}

fn from_api_dnc(bi: &api::BlindInfoForSigner) -> VCAResult<DncBlindInfo> {
    from_api(bi)
}
fn to_api_dnc(payload: DncBlindInfo) -> VCAResult<api::BlindInfoForSigner> {
    to_api(payload)
}

macro_rules! gen_tests {
    ($($modname:ident, $crypto:expr, $payload_ty:ty, $tamper:expr, $from_api_fn:expr, $to_api_fn:expr, $expect:expr);+ $(;)?) => {
        $(mod $modname {
            use super::*;
            #[test]
            fn blind_sign_roundtrip_ok() {
                let api = implement_vca_api_using($crypto);
                let expect: Option<fn(&Error) -> bool> = $expect;
                let res = run_blind_sign_roundtrip::<$payload_ty>(
                    api,
                    $tamper,
                    $from_api_fn,
                    $to_api_fn,
                );
                match expect {
                    None => assert!(res.is_ok(), "{res:?}"),
                    Some(pred) => match res {
                        Ok(_) => panic!("expected error, got success"),
                        Err(e) => assert!(pred(&e), "unexpected error: {e:?}"),
                    },
                }
            }
        })+
    };
}

// Generate happy-path tests for each backend; no tampering.
gen_tests!(
    ac2c_bbs, &CRYPTO_INTERFACE_AC2C_BBS, BlindCredentialRequest<BbsScheme>, do_not_tamper, from_api_ac2c_bbs, to_api_ac2c_bbs, None;
    ac2c_ps,  &CRYPTO_INTERFACE_AC2C_PS,  BlindCredentialRequest<PsScheme>,  do_not_tamper, from_api_ac2c_ps,  to_api_ac2c_ps,  None;
    dnc,      &CRYPTO_INTERFACE_DNC,      DncBlindInfo,                      do_not_tamper, from_api_dnc,      to_api_dnc,      None;
);

// Generate tamper tests expecting an error.
gen_tests!(
    ac2c_bbs_tamper,       &CRYPTO_INTERFACE_AC2C_BBS, BlindCredentialRequest<BbsScheme>, ac2c_tamper_commitment, from_api_ac2c_bbs, to_api_ac2c_bbs, Some(expect_invalid_signing);
    ac2c_bbs_tamper_proof, &CRYPTO_INTERFACE_AC2C_BBS, BlindCredentialRequest<BbsScheme>, ac2c_tamper_proof_bbs,  from_api_ac2c_bbs, to_api_ac2c_bbs, Some(expect_invalid_signing);
    ac2c_ps_tamper,        &CRYPTO_INTERFACE_AC2C_PS,  BlindCredentialRequest<PsScheme>,  ac2c_tamper_commitment, from_api_ac2c_ps,  to_api_ac2c_ps,  Some(expect_invalid_signing);
    ac2c_ps_tamper_proof,  &CRYPTO_INTERFACE_AC2C_PS,  BlindCredentialRequest<PsScheme>,  ac2c_tamper_proof_ps,   from_api_ac2c_ps,  to_api_ac2c_ps,  Some(expect_invalid_signing);
    // Try replacing the commitment with an alternative one, accept any failure.  Test fails because DNC does not create/verify proof of knowledge of blinder, so signing succeeds.
    dnc_tamper,            &CRYPTO_INTERFACE_DNC,      DncBlindInfo,                      alternative_tamper,     from_api_dnc,      to_api_dnc,      Some(any_failure_will_do);
);
