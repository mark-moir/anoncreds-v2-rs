use credx::vca::api::VcaApi;
use credx::vca::api_utils::implement_vca_api_using;
use credx::vca::types as api;
use credx::vca::types::ProofMode;
use credx::vca::types::ProofMode::Strict;
use credx::vca::VCAResult;

#[macro_export]
macro_rules! gen_blind_signing_tests {
    ($($modname:ident, $crypto:expr, $payload_ty:ty, $tamper:expr, $from_api_fn:expr, $to_api_fn:expr, $expect:expr);+ $(;)?) => {
        $(mod $modname {
            use super::*;
            #[test]
            fn blind_sign_roundtrip_ok() {
                use $crate::vca::zkp_functionality_tests::blind_signing_common as common;
                let api = common::api_for($crypto);
                let expect: Option<fn(&credx::vca::Error) -> bool> = $expect;
                let res = common::run_blind_sign_roundtrip::<$payload_ty>(
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

#[macro_export]
macro_rules! blind_signing_happy_path {
    ($name:ident, $crypto:expr) => {
        #[test]
        fn $name() {
            use $crate::vca::zkp_functionality_tests::blind_signing_common as common;
            let api = common::api_for($crypto);
            let res = common::run_blind_sign_roundtrip::<api::BlindSigningInfo>(
                api,
                common::do_not_tamper,
                common::from_api_identity,
                common::to_api_identity,
            );
            assert!(res.is_ok(), "{res:?}");
        }
    };
}

pub fn schema() -> Vec<api::ClaimType> {
    vec![
        api::ClaimType::CTText,
        api::ClaimType::CTInt, // blinded
        api::ClaimType::CTText,
        api::ClaimType::CTInt,
        api::ClaimType::CTAccumulatorMember,
    ]
}

pub fn blinded_idx() -> Vec<api::CredAttrIndex> {
    vec![1]
}

pub fn blinded_vals_good() -> Vec<api::CredAttrIndexAndDataValue> {
    vec![api::CredAttrIndexAndDataValue {
        index: 1,
        value: api::DataValue::DVInt(42),
    }]
}

pub fn blinded_vals_alt() -> Vec<api::CredAttrIndexAndDataValue> {
    vec![api::CredAttrIndexAndDataValue {
        index: 1,
        value: api::DataValue::DVInt(7),
    }]
}

pub fn non_blinded_vals() -> Vec<api::CredAttrIndexAndDataValue> {
    vec![
        (0, api::DataValue::DVText("meta".to_string())),
        (2, api::DataValue::DVText("ssn".to_string())),
        (3, api::DataValue::DVInt(180)),
        (
            4,
            api::DataValue::DVText("abcdef0123456789abcdef0123456789".to_string()),
        ),
    ]
    .into_iter()
    .map(|(i, v)| api::CredAttrIndexAndDataValue { index: i, value: v })
    .collect()
}

const TEST_NONCE: &str = "test-nonce";

pub fn build_blind_infos(
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

    let sd = create_signer_data(0, &schema, &blinded_idx, Strict)?;
    let nonce = TEST_NONCE.to_string();
    let bsi_good =
        create_blind_info(0, &nonce, &sd.signer_public_data, &blinded_vals_good(), Strict)?;
    let bsi_alt =
        create_blind_info(0, &nonce, &sd.signer_public_data, &blinded_vals_alt(), Strict)?;

    Ok((bsi_good, bsi_alt, sd, non_blinded, schema))
}

pub fn run_blind_sign(
    api: VcaApi,
    bifs_builder: impl FnOnce(
        &api::BlindSigningInfo,
        &api::BlindSigningInfo,
    ) -> VCAResult<api::BlindSigningInfo>,
) -> VCAResult<()> {
    let (bsi_good, bsi_alt, signer_data, non_blinded, schema) = build_blind_infos(&api)?;
    let blind_info = bifs_builder(&bsi_good, &bsi_alt)?;

    (api.verify_blind_signing_info_correctness_proof.clone())(
        &signer_data.signer_public_data.signer_public_setup_data,
        &signer_data.signer_public_data.signer_blinded_attr_idxs,
        &TEST_NONCE.to_string(),
        &blind_info.blind_info_for_signer,
    )?;

    let blinded_sig = (api.sign_with_blinded_attributes.clone())(
        0,
        &non_blinded,
        &blind_info.blind_info_for_signer,
        &signer_data,
        ProofMode::Strict,
    )?;
    (api.unblind_blinded_signature.clone())(
        &schema,
        &bsi_good.blinded_attributes,
        &blinded_sig,
        &bsi_good.info_for_unblinding,
        ProofMode::Strict,
    )?;

    Ok(())
}

pub fn run_blind_sign_roundtrip<T: Clone>(
    api: VcaApi,
    tamper: impl Fn(T, T) -> T,
    from_api_fn: fn(&api::BlindSigningInfo) -> VCAResult<T>,
    to_api_fn: fn(T) -> VCAResult<api::BlindSigningInfo>,
) -> VCAResult<()> {
    run_blind_sign(api, |good, alt| {
        let payload_good = from_api_fn(good)?;
        let payload_alt = from_api_fn(alt)?;
        let payload_use = tamper(payload_good, payload_alt);
        to_api_fn(payload_use)
    })
}

pub fn do_not_tamper<T>(g: T, _a: T) -> T {
    g
}

pub fn api_for(crypto: &credx::vca::interfaces::crypto_interface::CryptoInterface) -> VcaApi {
    implement_vca_api_using(crypto)
}

pub fn from_api_identity(bi: &api::BlindSigningInfo) -> VCAResult<api::BlindSigningInfo> {
    Ok(bi.clone())
}

pub fn to_api_identity(payload: api::BlindSigningInfo) -> VCAResult<api::BlindSigningInfo> {
    Ok(payload)
}
