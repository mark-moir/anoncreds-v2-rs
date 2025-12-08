// ----------------------------------------------------------------------------
use credx::vca::api;
use credx::vca::types::ProofMode;
use credx::vca::types::ProofMode::*;
use credx::vca::r#impl::json::util::encode_to_text;
use credx::vca::r#impl::util::{merge_maps, pp, three_lvl_map_to_vec_of_tuples};
// ----------------------------------------------------------------------------
use crate::vca::data_for_tests as td;
use crate::vca::test_framework as tf;
use crate::vca::test_framework::utility_functions::*;
// ----------------------------------------------------------------------------
use std::fmt::Debug;
use lazy_static::lazy_static;
use maplit::hashmap;
use std::collections::HashMap;
use std::hash::Hash;
// ----------------------------------------------------------------------------

// These are the same as the definitions in generate-tests-from-json/src/lib.rs,
// but we cannot import them from there because of limitations of what proc_macro crates
// can currently export.
pub type TestLabel = &'static str; // this is String in generate-tests-from-json/src/lib.rs
pub type LibrarySpecificTestHandlers = HashMap<TestLabel, TestHandler>;

#[derive(Clone)]
pub enum TestHandler {
    Skip(&'static str),
    Fail(&'static str),
    NotSoSlow,
}

#[macro_export]
macro_rules! per_crypto_library_test {
    ($crypto_interface: expr, $lib_spec: expr) => {
        mod spec {
            // -----------------------------------------------------------------------------
            use super::*;
            use credx::vca::api::*;
            use credx::vca::r#impl::util::*;
            // -----------------------------------------------------------------------------
            use $crate::vca::data_for_tests as td;
            // -----------------------------------------------------------------------------

            $crate::pok_and_reveal_metadata_test! {
                &credx::vca::api_utils::implement_vca_api_using(&$crypto_interface)
            }
            $crate::sign_create_verify_test! {
                &credx::vca::api_utils::implement_vca_api_using(&$crypto_interface),
                $lib_spec
            }
            // decrReqUnitSpec
            // accumAddRemoveSpec
            $crate::look_at_warnings_test! {
                &credx::vca::api_utils::implement_vca_api_using($crypto_interface),
                $lib_spec
            }
        }
    };
}

pub fn sign_d_cred(h_lbl: tf::HolderLabel) -> tf::TestStep {
    tf::TestStep::SignCredential(td::D_ISSUER_LABEL.to_owned(), h_lbl, td::D_VALS.to_owned(), None, Strict)
}

pub fn sign_s_cred(h_lbl: tf::HolderLabel) -> tf::TestStep {
    tf::TestStep::SignCredential(td::S_ISSUER_LABEL.to_owned(), h_lbl, td::S_VALS.to_owned(), None, Strict)
}

lazy_static! {
    pub static ref CREATE_D_ISSUER: tf::TestStep =
        tf::TestStep::CreateIssuer(td::D_ISSUER_LABEL.to_owned(), td::D_CTS.to_vec(), Vec::new(), TestBackend);
    pub static ref CREATE_D_ISSUER_WITH_VE: tf::TestStep =
        tf::TestStep::CreateIssuer(td::D_ISSUER_LABEL.to_owned(), td::D_CTS_WITH_VE.to_vec(), Vec::new(), TestBackend);
    pub static ref CREATE_S_ISSUER: tf::TestStep =
        tf::TestStep::CreateIssuer(td::S_ISSUER_LABEL.to_owned(), td::S_CTS.to_vec(), Vec::new(), TestBackend);
    pub static ref CREATE_POLICE_AUTHORITY: tf::TestStep =
        tf::TestStep::CreateAuthority(td::POLICE_AUTHORITY_LABEL.to_owned());
    pub static ref ENCRYPT_FOR_POLICE_AUTHORITY: tf::TestStep =
        tf::TestStep::EncryptFor(td::HOLDER_1.to_owned(),
                                 td::D_ISSUER_LABEL.to_owned(),
                                 td::D_SSN_IDX,
                                 td::POLICE_AUTHORITY_LABEL.to_owned());
    pub static ref DECRYPT_FOR_POLICE_AUTHORITY: tf::TestStep =
        tf::TestStep::Decrypt(td::HOLDER_1.to_owned(),
                              td::D_ISSUER_LABEL.to_owned(),
                              td::D_SSN_IDX,
                              td::POLICE_AUTHORITY_LABEL.to_owned());
}

pub fn succeeds_with_mode (proof_mode: ProofMode) ->
    Vec<tf::TestStep> {
        vec![tf::TestStep::CreateAndVerifyProof(
                "Holder1".to_string(),
                proof_mode,
                tf::CreateVerifyExpectation::BothSucceedNoWarnings
        )]
    }

pub fn proof_fails_with_mode (proof_mode: ProofMode, l: Vec<String>) ->
    Vec<tf::TestStep> {
        vec![tf::TestStep::CreateAndVerifyProof(
                "Holder1".to_string(),
                proof_mode,
                tf::CreateVerifyExpectation::CreateProofFails(l)
        )]
    }

pub fn proof_fails_with (l: Vec<String>) ->
    Vec<tf::TestStep> {
        proof_fails_with_mode(Strict,l)
    }

lazy_static! {
    pub static ref CREATE_ISSUERS: Vec<tf::TestStep> =
        vec![CREATE_D_ISSUER.to_owned(), CREATE_S_ISSUER.to_owned()];
    pub static ref CREATE_ACCUMS: Vec<tf::TestStep> = vec![
        tf::TestStep::CreateAccumulators(td::D_ISSUER_LABEL.to_owned()),
        tf::TestStep::CreateAccumulators(td::S_ISSUER_LABEL.to_owned())
    ];
    pub static ref SIGN_CREDS: Vec<tf::TestStep> = vec![
        sign_d_cred("Holder1".to_string()),
        sign_s_cred("Holder1".to_string()),
    ];
    pub static ref REVEAL_METADATA: Vec<tf::TestStep> = vec![
        tf::TestStep::Reveal(
            "Holder1".to_string(),
            td::D_ISSUER_LABEL.to_owned(),
            vec![td::D_META_IDX]
        ),
        tf::TestStep::Reveal(
            "Holder1".to_string(),
            td::S_ISSUER_LABEL.to_owned(),
            vec![td::S_META_IDX]
        )
    ];
    pub static ref COMMON_SETUP: Vec<tf::TestStep> = [
        CREATE_ISSUERS.to_owned(),
        CREATE_ACCUMS.to_owned(),
        SIGN_CREDS.to_owned(),
        REVEAL_METADATA.to_owned()
    ]
    .concat();

    pub static ref SUCCEEDS: Vec<tf::TestStep> = succeeds_with_mode(Strict);

    pub static ref FAILS: Vec<tf::TestStep> = proof_fails_with(vec!());

    pub static ref POK_AND_REVEAL_METADATA: Vec<tf::TestStep> =
        [COMMON_SETUP.to_owned(), SUCCEEDS.to_owned()].concat();
    pub static ref ADD_TO_ACCUMS: Vec<tf::TestStep> = vec![
        tf::TestStep::AccumulatorAddRemove(
            td::D_ISSUER_LABEL.to_owned(),
            td::D_ACCUM_IDX,
            hashmap!(td::HOLDER_1.to_owned() => td::D_VALS[td::D_ACCUM_IDX as usize].to_owned()),
            vec![]
        ),
        tf::TestStep::AccumulatorAddRemove(
            td::S_ISSUER_LABEL.to_owned(),
            td::S_ACCUM_IDX,
            hashmap!(td::HOLDER_1.to_owned() => td::D_VALS[td::S_ACCUM_IDX as usize].to_owned()),
            vec![]
        )
    ];
}

// This is here to satisfy type requirements but will need to be updated for real tests
pub const SOME_SEQUENCE_NUMBER: api::AccumulatorBatchSeqNo = 99;

lazy_static! {
    pub static ref IN_ACCUM_REQS: Vec<tf::TestStep> = vec![
        tf::TestStep::InAccum(
            "Holder1".to_string(),
            td::D_ISSUER_LABEL.to_owned(),
            td::D_ACCUM_IDX,
            SOME_SEQUENCE_NUMBER
        ),
        tf::TestStep::InAccum(
            "Holder1".to_owned(),
            td::S_ISSUER_LABEL.to_owned(),
            td::S_ACCUM_IDX,
            SOME_SEQUENCE_NUMBER
        )
    ];
    pub static ref SIGN_SECOND_DL: Vec<tf::TestStep> = vec![tf::TestStep::SignCredential(
        td::D_ISSUER_LABEL.to_owned(),
        "Holder2".to_owned(),
        td::D_VALS2.to_owned(),
        None,
        Strict
    )];
    pub static ref ADD_TO_ACCUM2: Vec<tf::TestStep> = vec![tf::TestStep::AccumulatorAddRemove(
        td::D_ISSUER_LABEL.to_owned(),
        td::D_ACCUM_IDX,
        hashmap!("Holder2".to_string() => td::D_VALS2[td::D_ACCUM_IDX as usize].to_owned()),
        vec![]
    )];
}

#[macro_export]
macro_rules! pok_and_reveal_metadata_test {
    ($vca_api: expr) => {
        #[test]
        fn pok_and_reveal_metadata() {
            use $crate::vca::test_framework::start_test;
            start_test($vca_api, POK_AND_REVEAL_METADATA.to_owned())
                .unwrap();
        }
    };
}

#[macro_export]
macro_rules! sign_create_verify_test {
    ($vca_api: expr, $lib_spec: expr) => {
        mod sign_create_verify {
            use super::*;
            use credx::vca::api::types::ProofMode::*;

            $crate::pok_test! { $vca_api, $lib_spec }
            $crate::revealed_test! { $vca_api, $lib_spec }
            $crate::equalities_test! { $vca_api, $lib_spec }
            $crate::range_test! { $vca_api, $lib_spec }
            $crate::warnings_test! { $vca_api, $lib_spec }
        }
    };
}

#[macro_export]
macro_rules! pok_test {
    ($vca_api: expr, $lib_spec: expr) => {
        #[test]
        fn pok_no_reveal() {
            let (_, _, d_sig_cd, s_sig_cd, shared) =
                do_create_signers_shared_and_sigs($vca_api);
            let proof_reqs: HashMap<CredentialLabel, CredentialReqs> = td::proof_reqs_with(
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            );
            expect(
                $vca_api,
                $lib_spec,
                &proof_reqs,
                &shared,
                &d_sig_cd,
                &s_sig_cd,
                &hashmap!(),
                Strict
            );
        }
    };
}

#[derive(Debug)]
pub enum RevealedState { Correct, Empty, Less, Change, More }

#[macro_export]
macro_rules! revealed_test {
    ($vca_api: expr, $lib_spec: expr) => {
        mod revealed_index_checks {
            use super::*;

            lazy_static! {
                static ref SHARED_AND_SIGS: SignersAndSigs =
                    do_create_signers_shared_and_sigs($vca_api);
                // Since destructuring is not allowed on LHS of a `static ref`
                // definition, must destructure `SHARED_AND_SIGS` as new
                // `static ref`s.
                static ref D_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.2.to_owned();
                static ref S_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.3.to_owned();
                static ref SHARED: HashMap<SharedParamKey, SharedParamValue> =
                    SHARED_AND_SIGS.4.to_owned();
            }

            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_correct, RevealedState::Correct, TestBackend }
            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_empty  , RevealedState::Empty,   TestBackend }
            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_less   , RevealedState::Less,    TestBackend }
            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_change , RevealedState::Change,  TestBackend }
            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_more   , RevealedState::More,    TestBackend }

            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_correct, RevealedState::Correct, Strict }
            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_empty  , RevealedState::Empty,   Strict }
            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_less   , RevealedState::Less,    Strict }
            // We do not test Change in Strict mode, because the values are revealed for the
            // correct indices and wrong values, which presentation_request_setup is not expected
            // to catch
            $crate::test_verify_disclosed!
              { $vca_api, $lib_spec, verify_disclosed_more   , RevealedState::More,    Strict }

            $crate::test_in_range! { $vca_api, $lib_spec, 0, revealed_0 }
            $crate::test_in_range! { $vca_api, $lib_spec, 3, revealed_3 }

            $crate::test_out_of_range! { $vca_api, $lib_spec, 5  , index_out_of_bounds_5   }
            $crate::test_out_of_range! { $vca_api, $lib_spec, 200, index_out_of_bounds_200 }
        }
    };
}

#[macro_export]
macro_rules! test_verify_disclosed {
    ($vca_api: expr, $lib_spec: expr, $name: ident, $revealed_state: expr, $prfmode: expr) => {
        paste::item! {
            #[test]
            fn [<test_ $name _ $prfmode:lower>]() {
                let proof_reqs = td::proof_reqs_with(
                    (vec![0], vec![0]),
                    (vec![], vec![]),
                    (vec![], vec![]),
                    (vec![], vec![]),
                    (vec![], vec![]));
                expect_disclosed($vca_api, $lib_spec, &proof_reqs, &SHARED,
                                 &D_SIG_CD, &S_SIG_CD, &hashmap!(), $revealed_state, $prfmode);
            }
        }
    };
}

#[macro_export]
macro_rules! test_in_range {
    ($vca_api: expr, $lib_spec: expr, $i: expr, $name: ident) => {
        #[test]
        fn $name() {
            let proof_reqs = td::proof_reqs_with(
                (vec![$i], vec![0]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            );
            expect(
                $vca_api,
                $lib_spec,
                &proof_reqs,
                &SHARED,
                &D_SIG_CD,
                &S_SIG_CD,
                &hashmap!(),
                TestBackend
            );
        }
    };
}

#[macro_export]
macro_rules! test_out_of_range {
    ($vca_api: expr, $lib_spec: expr, $i: expr, $name: ident) => {
        #[test]
        fn $name() {
            let proof_reqs = td::proof_reqs_with(
                (vec![$i], vec![0]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            );
            expect_create_proof_to_throw(
                $vca_api,
                &proof_reqs,
                &SHARED,
                &D_SIG_CD,
                &S_SIG_CD,
                Strict,
                |err| {
                    let err_str = format!("{err:?}");
                    let err_infix = format!("General(\"indexes; [{}]; out of range for; 5; attributes\")", $i);
                    assert!(
                        err_str.contains(&err_infix),
                        "expected error infix \"{err_infix}\" but the actual error is \"{err_str}\""
                    );
                },
            );
        }
    };
}

#[macro_export]
macro_rules! equalities_test {
    ($vca_api: expr, $lib_spec: expr) => {
        #[test]
        fn one_equality() {
            let (_, _, d_sig_cd, s_sig_cd, shared) =
                do_create_signers_shared_and_sigs($vca_api);
            let proof_reqs = td::proof_reqs_with(
                (vec![3], vec![0]),
                (vec![], vec![]),
                (vec![], vec![]),
                (
                    vec![credx::vca::types::EqInfo {
                        from_index: 2,
                        to_label: td::S_CRED_LABEL.to_string(),
                        to_index: 3,
                    }],
                    vec![credx::vca::types::EqInfo {
                        from_index: 3,
                        to_label: td::D_CRED_LABEL.to_string(),
                        to_index: 2,
                    }],
                ),
                (vec![], vec![]),
            );
            expect(
                $vca_api,
                $lib_spec,
                &proof_reqs,
                &shared,
                &d_sig_cd,
                &s_sig_cd,
                &hashmap!(),
                Strict
            );
        }

        // TODO: tests for when equalities _shouldn't_ hold
    };
}

#[macro_export]
macro_rules! range_test {
    ($vca_api: expr, $lib_spec: expr) => {
        mod range_proofs {
            use super::*;
            use $crate::vca::test_utils::*;

            lazy_static! {
                static ref SHARED_AND_SIGS: SignersAndSigs =
                    do_create_signers_shared_and_sigs_with_additional_setup(add_rng_prv_key, $vca_api);
                static ref D_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.2.to_owned();
                static ref S_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.3.to_owned();
                static ref SHARED: HashMap<SharedParamKey, SharedParamValue> =
                    SHARED_AND_SIGS.4.to_owned();
            }

            lazy_static! {
                static ref PROOF_REQS: HashMap<CredentialLabel, CredentialReqs> =
                    td::proof_reqs_with(
                        (vec![3], vec![0]),
                        (vec![], vec![]),
                        (
                            vec![InRangeInfo {
                                index: td::D_DOB_IDX.to_owned(),
                                min_label: MIN_BDDAYS_LBL.to_owned(),
                                max_label: MAX_BDDAYS_LBL.to_owned(),
                                range_proving_key_label: RPK_LBL.to_owned(),
                            }],
                            vec![InRangeInfo {
                                index: td::S_VALID_DAYS_IDX.to_owned(),
                                min_label: MIN_VALID_DAYS_LBL.to_owned(),
                                max_label: MAX_VALID_DAYS_LBL.to_owned(),
                                range_proving_key_label: RPK_LBL.to_owned(),
                            }],
                        ),
                        (vec![], vec![]),
                        (vec![], vec![]),
                    );
            }

            #[test]
            // TODO: use the slow_slow_test macro defined in utils
            #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"),ignore)]
            fn slowslow_in_range() {
                it_with($lib_spec, "RANGE_PROOF_IN_RANGE_GENERIC", || {
                    let shared = add_rng_params(SHARED.to_owned());
                    expect(
                        $vca_api,
                        $lib_spec,
                        &PROOF_REQS,
                        &shared,
                        &D_SIG_CD,
                        &S_SIG_CD,
                        &hashmap!(),
                        Strict
                    )
                });
            }

            #[test]
            // TODO: use the slow_slow_test macro defined in utils
            #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"),ignore)]
            fn slowslow_out_of_range_generic() {
                it_with($lib_spec, "RANGE_PROOF_OUT_OF_RANGE_GENERIC", || {
                    // Override minValiddays param *after* setting normal
                    // params, to ensure the range excludes the value in the
                    // credential.
                    let shared = add_rng_params_with_altered_range_to_exclude_signed_value(
                        SHARED.to_owned(),
                    );
                    expect_create_proof_to_throw(
                        $vca_api,
                        &PROOF_REQS,
                        &shared,
                        &D_SIG_CD,
                        &S_SIG_CD,
                        Strict,
                        |err| {
                            missing_case_insensitive_const(
                                "out_of_range_generic",
                                format!("{err:?}"),
                                &["validateProofInstructionsAgainstValues",
                                  "out of range",
                                  "attribute index"
                                ]).map(|err| panic!("{err:?}"));
                        }
                    );
                });
            }

            lazy_static! {
                static ref RPK_LBL: SharedParamKey = "rangeProvingKey".to_string();
                static ref MIN_BDDAYS_LBL: CredentialLabel = "minBDdays".to_string();
                static ref MAX_BDDAYS_LBL: CredentialLabel = "maxBDdays".to_string();
                static ref MIN_VALID_DAYS_LBL: CredentialLabel = "minValiddays".to_string();
                static ref MAX_VALID_DAYS_LBL: CredentialLabel = "maxValiddays".to_string();

                static ref S_VALID_DAYS_VAL: u64 = match td::S_VALS[td::S_VALID_DAYS_IDX as usize] {
                    DataValue::DVInt(v) => v,
                    _ => panic!("td::S_VALS[td::S_VALID_DAYS_IDX as usize] was not a DataValue::DVInt")
                };
            }

            fn add_rng_prv_key(
                mut shared: HashMap<SharedParamKey, SharedParamValue>,
            ) -> VCAResult<HashMap<SharedParamKey, SharedParamValue>> {
                let rpk = ($vca_api.create_range_proof_proving_key)(0)?;
                // println!("add_rng_prv_key: rpk: {:?}", rpk);
                let s = serde_json::to_string(&rpk).unwrap();
                // println!("add_rng_prv_key: encoded: {:?}", s);
                shared.insert(
                    RPK_LBL.to_string(),
                    SharedParamValue::SPVOne(DataValue::DVText(s)),
                );
                Ok(shared)
            }

            fn add_rng_params(
                mut shared: HashMap<SharedParamKey, SharedParamValue>,
            ) -> HashMap<SharedParamKey, SharedParamValue> {
                shared.insert(
                    MIN_BDDAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(37696)),
                );
                shared.insert(
                    MAX_BDDAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(999999999999)),
                );
                shared.insert(
                    MIN_VALID_DAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(0)),
                );
                shared.insert(
                    MAX_VALID_DAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(50000)),
                );
                shared
            }

            fn add_rng_params_with_altered_range_to_exclude_signed_value(
                mut shared: HashMap<SharedParamKey, SharedParamValue>,
            ) -> HashMap<SharedParamKey, SharedParamValue> {
                shared = add_rng_params(shared);
                shared.insert(
                    MIN_VALID_DAYS_LBL.to_owned(),
                    SharedParamValue::SPVOne(DataValue::DVInt(S_VALID_DAYS_VAL.to_owned() + 1)),
                );
                shared
            }
        }
    };
}

#[macro_export]
macro_rules! warnings_test {
    ($vca_api: expr, $lib_spec: expr) => {
        mod warnings_test {
            use super::*;

            $crate::reveal_privacy_warnings_test! { $vca_api, $lib_spec }
        }
    };
}

#[macro_export]
macro_rules! reveal_privacy_warnings_test {
    ($vca_api: expr, $lib_spec: expr) => {
        // TODO: currently this Spec only expects warnings from general, but we
        // should also have a way of expecting library-specific warnings, which
        // would be used in a libary-specific test where we know what
        // library-specific warnings to expect.
        mod reveal_privacy_warnings {
            use super::*;

            lazy_static! {
                static ref SHARED_AND_SIGS: SignersAndSigs =
                    do_create_signers_shared_and_sigs($vca_api);
                static ref D_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.2.to_owned();
                static ref S_SIG_CD: (Signature, Vec<DataValue>, AccumulatorWitnesses) =
                    SHARED_AND_SIGS.3.to_owned();
                static ref SHARED: HashMap<SharedParamKey, SharedParamValue> =
                    SHARED_AND_SIGS.4.to_owned();
            }

            fn all_indices<T>(cts: Vec<T>) -> Vec<u64> {
                (0..cts.len() as u64).collect()
            }

            fn minus_vec<T: PartialEq>(v1: Vec<T>, v2: &[T]) -> Vec<T> {
                v1.into_iter().filter(|x| !v2.contains(x)).collect()
            }

            // this comes from `beforeAll(doCreateSignersSharedAndSigs VcaApi)`
            lazy_static! {
                pub static ref D_CTS_WARNABLE_INDICES: Vec<u64> = vec![td::D_ACCUM_IDX];
                pub static ref S_CTS_WARNABLE_INDICES: Vec<u64> = vec![td::S_ACCUM_IDX];

                pub static ref D_CTS_NON_WARNABLE_INDICES: Vec<u64> =
                    minus_vec(D_CTS_ALL_INDICES.to_vec(), &D_CTS_WARNABLE_INDICES);
                pub static ref S_CTS_NON_WARNABLE_INDICES: Vec<u64> =
                    minus_vec(S_CTS_ALL_INDICES.to_vec(), &S_CTS_WARNABLE_INDICES);

                pub static ref D_ACCUM_WARNINGS: Vec<Warning> = vec![Warning::RevealPrivacyWarning(
                    td::D_CRED_LABEL.to_string(),
                    td::D_ACCUM_IDX,
                    "an accumulator member".to_string()
                )];
                pub static ref S_ACCUM_WARNINGS: Vec<Warning> = vec![Warning::RevealPrivacyWarning(
                    td::S_CRED_LABEL.to_string(),
                    td::S_ACCUM_IDX,
                    "an accumulator member".to_string()
                )];

                pub static ref D_CTS_ALL_INDICES: Vec<u64> = all_indices(td::D_CTS.to_vec());
                pub static ref S_CTS_ALL_INDICES: Vec<u64> = all_indices(td::S_CTS.to_vec());
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_D_CTS_WARNABLE_INDICES,
                D_CTS_WARNABLE_INDICES.to_vec(),
                vec![],
                D_ACCUM_WARNINGS.to_vec()
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_D_CTX_ALL_INDICES,
                D_CTS_ALL_INDICES.to_vec(),
                vec![],
                D_ACCUM_WARNINGS.to_vec()
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_D_CTX_NON_WARNABLE_INDICES,
                D_CTS_NON_WARNABLE_INDICES.to_vec(),
                vec![],
                vec![]
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_S_CTS_WARNABLE_INDICES,
                vec![],
                S_CTS_WARNABLE_INDICES.to_vec(),
                S_ACCUM_WARNINGS.to_vec()
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_S_CTX_ALL_INDICES,
                vec![],
                S_CTS_ALL_INDICES.to_vec(),
                S_ACCUM_WARNINGS.to_vec()
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_S_CTX_NON_WARNABLE_INDICES,
                vec![],
                S_CTS_NON_WARNABLE_INDICES.to_vec(),
                vec![]
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_D_CTS_WARNABLE_INDICES_and_S_CTS_WARNABLE_INDICES,
                D_CTS_WARNABLE_INDICES.to_vec(),
                S_CTS_WARNABLE_INDICES.to_vec(),
                [D_ACCUM_WARNINGS.to_vec(), S_ACCUM_WARNINGS.to_vec()].concat()
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_D_CTS_ALL_INDICES_and_S_CTS_ALL_INDICES,
                D_CTS_ALL_INDICES.to_vec(),
                S_CTS_ALL_INDICES.to_vec(),
                [D_ACCUM_WARNINGS.to_vec(), S_ACCUM_WARNINGS.to_vec()].concat()
            }

            $crate::expect_privacy_warnings!{
                $vca_api, $lib_spec, _revealed_D_CTS_NON_WARNABLE_INDICES_and_S_CTS_NON_WARNABLE_INDICES,
                D_CTS_NON_WARNABLE_INDICES.to_vec(),
                S_CTS_NON_WARNABLE_INDICES.to_vec(),
                vec![]
            }
        }
    };
}

#[macro_export]
macro_rules! expect_privacy_warnings {
    ($vca_api: expr, $lib_spec: expr, $suffix: ident, $d_revealed: expr, $s_revealed: expr, $ws: expr) => {
        #[test]
        #[allow(non_snake_case)]
        fn $suffix() {
            let proof_reqs = td::proof_reqs_with(
                ($d_revealed, $s_revealed),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
                (vec![], vec![]),
            );
            // println!(
            //     "expect_privacy_warnings: ws: {:?}",
            //     $ws as Vec<credx::vca::types::Warning>
            // );
            expect_with_warnings(
                |ws2| {
                    pp("expect_privacy_warnings from createProof", ws2);
                    assert!($ws.iter().all(|w| ws2.contains(w)))
                },
                |ws2| {
                    pp("expect_privacy_warnings from verifyProof", ws2);
                    assert!($ws.iter().all(|w| ws2.contains(w)))
                },
                $vca_api,
                $lib_spec,
                &proof_reqs,
                &SHARED,
                &D_SIG_CD,
                &S_SIG_CD,
                &hashmap!(),
                Loose
            )
        }
    };
}

#[macro_export]
macro_rules! look_at_warnings_test {
    ($vca_api: expr, $lib_spec: expr) => {
        fn all_indices<T>(cts: Vec<T>) -> Vec<u64> {
            (0..cts.len() as u64).collect()
        }

        fn minus_vec<T: PartialEq>(v1: Vec<T>, v2: &[T]) -> Vec<T> {
            v1.into_iter().filter(|x| !v2.contains(x)).collect()
        }

        // this comes from `beforeAll(doCreateSignersSharedAndSigs VcaApi)`
        lazy_static! {
            pub static ref D_CTS_WARNABLE_INDICES: Vec<u64> = vec![td::D_ACCUM_IDX];
            pub static ref S_CTS_WARNABLE_INDICES: Vec<u64> = vec![td::S_ACCUM_IDX];
            pub static ref D_CTS_NON_WARNABLE_INDICES: Vec<u64> =
                minus_vec(D_CTS_ALL_INDICES.to_vec(), &D_CTS_WARNABLE_INDICES);
            pub static ref S_CTS_NON_WARNABLE_INDICES: Vec<u64> =
                minus_vec(S_CTS_ALL_INDICES.to_vec(), &S_CTS_WARNABLE_INDICES);
            pub static ref D_ACCUM_WARNINGS: Vec<Warning> = vec![Warning::RevealPrivacyWarning(
                td::D_CRED_LABEL.to_string(),
                td::D_ACCUM_IDX,
                "an accumulator member".to_string()
            )];
            pub static ref S_ACCUM_WARNINGS: Vec<Warning> = vec![Warning::RevealPrivacyWarning(
                td::S_CRED_LABEL.to_string(),
                td::S_ACCUM_IDX,
                "an accumulator member".to_string()
            )];
            pub static ref D_CTS_ALL_INDICES: Vec<u64> = all_indices(td::D_CTS.to_vec());
            pub static ref S_CTS_ALL_INDICES: Vec<u64> = all_indices(td::S_CTS.to_vec());
        }

        #[test]
        fn look_at_warnings_test() {
            print!(
                "D_CTS_WARNABLE_INDICES\n{:?}",
                D_CTS_WARNABLE_INDICES.to_owned()
            );
            print!(
                "S_CTS_WARNABLE_INDICES\n{:?}",
                S_CTS_WARNABLE_INDICES.to_owned()
            );
            print!(
                "D_CTS_NON_WARNABLE_INDICES\n{:?}",
                D_CTS_WARNABLE_INDICES.to_owned()
            );
            print!(
                "S_CTS_NON_WARNABLE_INDICES\n{:?}",
                S_CTS_WARNABLE_INDICES.to_owned()
            );
            print!("D_ACCUM_WARNINGS\n{:?}", D_ACCUM_WARNINGS.to_owned());
            print!("S_ACCUM_WARNINGS\n{:?}", S_ACCUM_WARNINGS.to_owned());
        }
    }
}

// Use this to mark a test as slowslow, so it gets skipped if EITHER of the ignore_slow and
// ignore_slow_slow features is enabled
#[macro_export]
macro_rules! slow_slow_test {
    () => {
        #[cfg_attr(any(feature = "ignore_slow", feature = "ignore_slow_slow"), ignore)]
    };
}

// Use this to mark a test as slow, so it gets skipped if ignore_slow feature is enabled,
// but will still be run if only the ignore_slow_slow feature is enabled
#[macro_export]
macro_rules! slow_test {
    () => {
        #[cfg_attr(feature = "ignore_slow", ignore)]
    };
}

pub fn it_with(lib_spec: &LibrarySpecificTestHandlers, label: TestLabel, k: impl Fn()) {
    match lib_spec.get(label) {
        None => k(),
        Some(TestHandler::NotSoSlow) => k(), // I can't quite directly translate the dynamic test label from Haskell
        Some(TestHandler::Skip(s)) => { println!("{:?} skipped because {:?}", label, s) },
        Some(TestHandler::Fail(s)) => panic!("not run because: {s}"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn expect_disclosed(
    vca_api        : &api::VcaApi,
    _lib_spec      : &LibrarySpecificTestHandlers,
    proof_reqs     : &HashMap<api::CredentialLabel, api::CredentialReqs>,
    shared         : &HashMap<api::SharedParamKey, api::SharedParamValue>,
    d_sig_cd       : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    s_sig_cd       : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    decrypt_reqs   : &HashMap<api::CredentialLabel,
                              HashMap<api::CredAttrIndex,
                                      HashMap<api::AuthorityLabel, api::DecryptRequest>>>,
    revealed_state : RevealedState,
    proof_mode     : ProofMode,
) {
    let api::WarningsAndDataForVerifier { data_for_verifier: dfv, .. } =
        match do_create_proof(vca_api, proof_reqs, shared, d_sig_cd, s_sig_cd, proof_mode) {
            Err(e) => panic!("expect_disclosed create_proof; unexpected failure; {e:?}"),
            Ok(x)  => x,
        };
    match revealed_state {
        RevealedState::Correct => {
            if let Err(e) = do_verify_proof(vca_api, proof_reqs, shared, dfv, decrypt_reqs, proof_mode) {
                panic!("'Correct' unexpected failure; {e:?}")
            };
        },
        RevealedState::Empty => {
            let dfv = api::DataForVerifier { revealed_idxs_and_vals : HashMap::new(), proof: dfv.proof };
            match do_verify_proof(vca_api, proof_reqs, shared, dfv, decrypt_reqs, proof_mode) {
                Err(api::Error::General(e)) => {
                    if ! e.contains("Unequal keys for maps to be merged") {
                        panic!("'Empty' failed in the wrong way; {e:?}");
                    }
                }
                x => panic_on_ok_or_wrong_error(RevealedState::Empty, x),
            };
        },
        RevealedState::Less   =>
            verify_proof_and_check_for_expected_outcome(
                RevealedState::Less,   vca_api, proof_reqs, shared, decrypt_reqs, proof_mode,
                // note: this removes the existing disclosure
                modify_data_for_verifier(dfv, None)),
        RevealedState::Change =>
            verify_proof_and_check_for_expected_outcome(
                RevealedState::Change, vca_api, proof_reqs, shared, decrypt_reqs, proof_mode,
                // note: change existing
                modify_data_for_verifier(dfv, Some((0, api::DataValue::DVText("WRONG".into()))))),
        RevealedState::More   =>
            verify_proof_and_check_for_expected_outcome(
                RevealedState::More,   vca_api, proof_reqs, shared, decrypt_reqs, proof_mode,
                // note: add a disclosure
                modify_data_for_verifier(dfv, Some((1, api::DataValue::DVText("EXTRA VALUE".into()))))),
    }

    fn verify_proof_and_check_for_expected_outcome(
        revealed_state : RevealedState,
        vca_api        : &api::VcaApi,
        proof_reqs     : &HashMap<api::CredentialLabel, api::CredentialReqs>,
        shared         : &HashMap<api::SharedParamKey, api::SharedParamValue>,
        decrypt_reqs   : &HashMap<api::CredentialLabel,
                                  HashMap<api::CredAttrIndex,
                                          HashMap<api::AuthorityLabel, api::DecryptRequest>>>,
        proof_mode     : ProofMode,
        dfv            : api::DataForVerifier
    ) {
        match do_verify_proof(vca_api, proof_reqs, shared, dfv, decrypt_reqs, proof_mode) {
            Err(api::Error::General(e)) => panic_on_wrong_general_error_msg(&e, revealed_state, proof_mode),
            x                           => panic_on_ok_or_wrong_error(revealed_state, x),
        };
    }

    fn contains_expected_error_messages(e: &str, prf_mode: ProofMode) -> bool {
        let ac2c_1 = "verify_disclosed_messages: disclosed_messages_from_proof";
        let ac2c_2 = "differ from revealed values";
        let dnc    = "DNC prf.verify BBSPlusProofContributionFailed(0, FirstSchnorrVerificationFailed)";
        let gen_1  = "get_proof_instructions_for_cred";
        let gen_2  = "do not match indexes requested";
        match prf_mode {
            TestBackend => (e.contains(ac2c_1) && e.contains(ac2c_2)) || e.contains(dnc),
            _           => e.contains(gen_1) && e.contains(gen_2)
        }
    }

    // The Option controls make the inner map of disclosed values for one credential:
    // - None : an empty map (essentially removing existing values)
    // - Some : set the attribute to the given value
    //          this either overwrites (if given an existing CredAttrIndex)
    //          or adds a new disclosure
    fn modify_data_for_verifier(
        dfv: api::DataForVerifier,
        inner_value: Option<(api::CredAttrIndex, api::DataValue)>
    ) -> api::DataForVerifier {
        let mut riav = dfv.revealed_idxs_and_vals;
        let inner = if let Some((idx, dv)) = inner_value {
            let mut inner = riav.get(&td::S_CRED_LABEL.clone()).expect("I know it is there").clone();
            inner.insert(idx, dv);
            inner
        } else {
            HashMap::new()
        };
        riav.insert(td::S_CRED_LABEL.clone(), inner).expect("It's still there");
        api::DataForVerifier { revealed_idxs_and_vals : riav, proof: dfv.proof }
    }

    fn panic_on_wrong_general_error_msg(
        e: &str,
        revealed_state: RevealedState,
        prf_mode: ProofMode) {
        if !contains_expected_error_messages(e, prf_mode) {
            panic!("'{revealed_state:?}' failed in the wrong way; {e:?}")
        }
    }

    fn panic_on_ok_or_wrong_error<T: Debug>(rs: RevealedState, x: T)  {
        panic!("{x:?} was 'Ok' or failed in the wrong way; {rs:?}")
    }
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
pub fn expect_flow_to_be_unsuccessful(
    vca_api      : &api::VcaApi,
    _lib_spec    : &LibrarySpecificTestHandlers,
    proof_reqs   : &HashMap<api::CredentialLabel, api::CredentialReqs>,
    shared       : &HashMap<api::SharedParamKey, api::SharedParamValue>,
    d_sig_cd     : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    s_sig_cd     : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    decrypt_reqs : &HashMap<api::CredentialLabel,
                            HashMap<api::CredAttrIndex,
                                    HashMap<api::AuthorityLabel, api::DecryptRequest>>>,
    proof_mode   : ProofMode
) {
    let api::WarningsAndDataForVerifier { data_for_verifier: dfv, .. } =
        match do_create_proof(vca_api, proof_reqs, shared, d_sig_cd, s_sig_cd, proof_mode.clone()) {
            Err(_) => return,
            Ok(x) => x,
        };
    let x = match do_verify_proof(vca_api, proof_reqs, shared, dfv, decrypt_reqs, proof_mode) {
        Err(_) => return,
        Ok(x) => x,
    };
    panic!("expected failure; but succeeded with; {x:?}");
}

#[allow(clippy::too_many_arguments)]
pub fn expect_with_warnings(
    expect_warns_from_create_proof : impl Fn(&[api::Warning]),
    expect_warns_from_verify_proof : impl Fn(&[api::Warning]),
    vca_api                        : &api::VcaApi,
    _lib_spec                      : &LibrarySpecificTestHandlers,
    proof_reqs                     : &HashMap<api::CredentialLabel, api::CredentialReqs>,
    shared                         : &HashMap<api::SharedParamKey, api::SharedParamValue>,
    d_sig_cd                       : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    s_sig_cd                       : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    decrypt_reqs                   : &HashMap<api::CredentialLabel,
                                              HashMap<api::CredAttrIndex,
                                                      HashMap<api::AuthorityLabel, api::DecryptRequest>>>,
    proof_mode   : ProofMode
) {
    // println!("EXPECT_WITH_WARNINGS");
    let api::WarningsAndDataForVerifier {
        warnings: warns_from_create_proof,
        data_for_verifier: dfv,
    }: api::WarningsAndDataForVerifier =
        do_create_proof(vca_api, proof_reqs, shared, d_sig_cd, s_sig_cd, proof_mode.clone()).unwrap();
    expect_warns_from_create_proof(&warns_from_create_proof);

    let discls = &dfv.revealed_idxs_and_vals;

    fn sort<T: Ord>(mut xs: Vec<T>) -> Vec<T> {
        xs.sort_unstable();
        xs
    }

    assert_eq!(
        sort(discls.clone().into_keys().collect::<Vec<_>>()),
        sort(vec![
            td::D_CRED_LABEL.to_string(),
            td::S_CRED_LABEL.to_string()
        ])
    );

    let validate_disclosures = |discls: &HashMap<api::CredentialLabel, HashMap<u64, api::DataValue>>,
                                c_lbl: &api::CredentialLabel,
                                vals: &[api::DataValue]|
     -> api::VCAResult<()> {
        let api::Disclosed(idxs) = &proof_reqs[c_lbl].disclosed;
        let idxs_and_vals = idxs
            .iter()
            .map(|idx| (*idx, vals[*idx as usize].clone()))
            .collect::<HashMap<_, _>>();
        let cred_discls = &discls[c_lbl];
        assert_eq!(&idxs_and_vals, cred_discls);
        Ok(())
    };

    vec![
        (td::D_CRED_LABEL.to_string(), td::D_VALS.to_vec()),
        (td::S_CRED_LABEL.to_string(), td::S_VALS.to_vec()),
    ]
    .into_iter()
    .for_each(|(cl, dvs)| validate_disclosures(discls, &cl, &dvs).unwrap());

    let api::WarningsAndDecryptResponses {
        warnings: warns_from_verify_proof,
        decrypt_responses: decrypt_rsps,
    } = do_verify_proof(vca_api, proof_reqs, shared, dfv, decrypt_reqs, proof_mode).unwrap();
    expect_warns_from_verify_proof(&warns_from_verify_proof);

    // TODO: Generalise so it works for arbitrary number of requests
    match three_lvl_map_to_vec_of_tuples(&decrypt_rsps).as_slice() {
        [] => {
            assert_eq!(decrypt_rsps, hashmap! {});
        }
        [(cl, ai, a_lbl, api::DecryptResponse { .. })] => {
            let api::DataValue::DVText(t) = &td::D_VALS[**ai as usize] else {
                panic!("invalid DataValue in test_data::D_VALS")
            };
            let api::DecryptResponse { value: t_, .. } = &decrypt_rsps[*cl][*ai][*a_lbl];
            assert_eq!(t_, t); // THIS IS IT! <----------------
        }
        _ => panic!("invalid decrypt_rsps_vec"),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn expect(
    vca_api      : &api::VcaApi,
    lib_spec     : &LibrarySpecificTestHandlers,
    proof_reqs   : &HashMap<api::CredentialLabel, api::CredentialReqs>,
    shared       : &HashMap<api::SharedParamKey, api::SharedParamValue>,
    d_sig_cd     : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    s_sig_cd     : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    decrypt_reqs : &HashMap<api::CredentialLabel,
                            HashMap<api::CredAttrIndex,
                                    HashMap<api::AuthorityLabel,api::DecryptRequest>>>,
    proof_mode   : ProofMode
) {
    expect_with_warnings(
        |ws| {
            assert!(
                ws.is_empty(),
                "expected no warnings from `create_proof`, but got: {:?}",
                ws
            )
        },
        |ws| {
            assert!(
                ws.is_empty(),
                "expected no warnings from `verify_proof`, but got: {:?}",
                ws
            )
        },
        vca_api,
        lib_spec,
        proof_reqs,
        shared,
        d_sig_cd,
        s_sig_cd,
        decrypt_reqs,
        proof_mode
    )
}

pub fn expect_create_proof_to_throw(
    vca_api        : &api::VcaApi,
    proof_reqs     : &HashMap<api::CredentialLabel, api::CredentialReqs>,
    shared         : &HashMap<api::SharedParamKey, api::SharedParamValue>,
    dsig_cd        : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    ssig_cd        : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    proof_mode     : ProofMode,
    fail_condition : impl Fn(&api::Error),
) {
    match do_create_proof(vca_api, proof_reqs, shared, dsig_cd, ssig_cd, proof_mode) {
        Err(err) => fail_condition(&err),
        Ok(_)    => panic!("create_proof expected to throw an error, but succeeded")
    }
}

// TODO: expect_verification_to_throw

#[allow(clippy::type_complexity)]
pub fn do_test_setup_with_additional_setup(
    update_sp    : fn(
        HashMap<api::SharedParamKey, api::SharedParamValue>,
    ) -> api::VCAResult<HashMap<api::SharedParamKey, api::SharedParamValue>>,
    vca_api      : &api::VcaApi,
    signers      : &HashMap<tf::IssuerLabel, Vec<api::ClaimType>>,
    creds        : &HashMap<api::CredentialLabel, (tf::IssuerLabel, Vec<api::DataValue>)>,
) -> (
    HashMap<tf::IssuerLabel, api::SignerData>,
    HashMap<api::CredentialLabel, (api::Signature, HashMap<api::CredAttrIndex, api::AccumulatorWitnesses>)>,
    HashMap<api::SharedParamKey, api::SharedParamValue>,
) {
    let signer_data: HashMap<tf::IssuerLabel, api::SignerData> = signers
        .iter()
        .enumerate()
        .map(|(i, (s_lbl, schema))| {
            (
                s_lbl.clone(),
                (vca_api.create_signer_data)(i as u64, schema, &[], Strict).unwrap(),
            )
        })
        .collect();

    let go = |signer_data: &HashMap<tf::IssuerLabel, api::SignerData>,
              (i_lbl, vals): &(tf::IssuerLabel, Vec<api::DataValue>)|
     -> api::Signature { (vca_api.sign)(0, vals, &signer_data[i_lbl], Strict).unwrap() };

    let sigs: HashMap<tf::IssuerLabel, api::Signature> = creds
        .iter()
        .map(|(k, v)| (k.clone(), go(&signer_data, v)))
        .collect();

    let create_wits_for = |(i_lbl, _)| -> HashMap<api::CredAttrIndex, HashMap<_, _>> {
        create_for_accumulator_fields(&signers[i_lbl], |_| Ok(hashmap!())).unwrap()
    };

    let wits: HashMap
        <api::CredentialLabel,
         HashMap<api::CredAttrIndex,
                 HashMap<api::CredAttrIndex, api::AccumulatorMembershipWitness>>,
    > = creds
        .iter()
        .map(|(k, (i_lbl, dvs))| (k.clone(), create_wits_for((i_lbl, dvs))))
        .collect();

    let sigs_and_wits: HashMap
        <api::CredentialLabel,
         (api::Signature,
          HashMap<api::CredAttrIndex,
                  HashMap<api::CredAttrIndex, api::AccumulatorMembershipWitness>>,
        ),
    > = merge_maps(sigs, wits).unwrap();

    let shared_params: HashMap<tf::IssuerLabel, api::SharedParamValue> = signer_data
        .iter()
        .map(|(k, v)| {
            (
                k.clone(),
                api::SharedParamValue::SPVOne(api::DataValue::DVText(
                    encode_to_text(&v.signer_public_data).unwrap(),
                )),
            )
        })
        .collect();

    let shared_params_ = update_sp(shared_params).unwrap();

    (signer_data, sigs_and_wits, shared_params_)
}

#[allow(clippy::type_complexity, unused)]
pub fn do_test_setup(
    vca_api      : &api::VcaApi,
    signers      : &HashMap<tf::IssuerLabel, Vec<api::ClaimType>>,
    creds        : &HashMap<api::CredentialLabel, (tf::IssuerLabel, Vec<api::DataValue>)>,
) -> (
    HashMap<api::CredentialLabel, api::SignerData>,
    HashMap<api::CredentialLabel,
            (api::Signature, HashMap<u64, api::AccumulatorWitnesses>)>,
    HashMap<api::SharedParamKey, api::SharedParamValue>,
) {
    do_test_setup_with_additional_setup(Ok, vca_api, signers, creds)
}

pub type SignersAndSigs = (
    api::SignerData,
    api::SignerData,
    (api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    (api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    HashMap<api::SharedParamKey, api::SharedParamValue>,
);

pub fn do_create_signers_shared_and_sigs(vca_api: &api::VcaApi) -> SignersAndSigs {
    do_create_signers_shared_and_sigs_with_additional_setup(Ok, vca_api)
}

#[allow(clippy::type_complexity)]
pub fn do_create_signers_shared_and_sigs_with_additional_setup(
    update_sp : fn(
        HashMap<api::SharedParamKey, api::SharedParamValue>,
    ) -> api::VCAResult<HashMap<api::SharedParamKey, api::SharedParamValue>>,
    vca_api   : &api::VcaApi,
) -> SignersAndSigs {
    let (signer_data, sigs_and_aux, shared) = do_test_setup_with_additional_setup(
        update_sp,
        vca_api,
        &td::DEFAULT_ISSUERS,
        &td::DEFAULT_CREDS,
    );

    // Map k a -> Map k1 (a1, Map k2 c) -> k -> k1 -> k2 -> (a, a1, c)
    fn get_tuple<'a, 'b, K: Eq + Hash, A, K1: Eq + Hash, A1, K2: Eq + Hash, C>(
        sd: &'a HashMap<K, A>,
        saa: &'b HashMap<K1, (A1, HashMap<K2, C>)>,
        i_lbl: &K,
        c_lbl: &K1,
        acc_idx: &K2,
    ) -> (&'a A, &'b A1, &'b C) {
        (&sd[i_lbl], &saa[c_lbl].0, &saa[c_lbl].1[acc_idx])
    }

    let (dsd, d, d_aux) = get_tuple(
        &signer_data,
        &sigs_and_aux,
        &td::D_SPD_KEY,
        &td::D_CRED_LABEL,
        &td::D_ACCUM_IDX,
    );
    let (ssd, s, s_aux) = get_tuple(
        &signer_data,
        &sigs_and_aux,
        &td::S_SPD_KEY,
        &td::S_CRED_LABEL,
        &td::S_ACCUM_IDX,
    );

    // BONUS: rather than cloning everything, I could thoughtfully propogate
    // lifetimes in SignersAndSigs
    (
        dsd.clone(),
        ssd.clone(),
        (d.clone(), td::D_VALS.clone(), d_aux.clone()),
        (s.clone(), td::S_VALS.clone(), s_aux.clone()),
        shared,
    )
}

pub fn do_create_proof(
    vca_api                 : &api::VcaApi,
    proof_reqs              : &HashMap<api::CredentialLabel, api::CredentialReqs>,
    shared                  : &HashMap<api::SharedParamKey, api::SharedParamValue>,
    (d_sig, d_vals, d_wits) : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    (s_sig, s_vals, s_wits) : &(api::Signature, Vec<api::DataValue>, api::AccumulatorWitnesses),
    proof_mode              : ProofMode
) -> api::VCAResult<api::WarningsAndDataForVerifier> {
    let wr = (*vca_api.create_proof)(
        proof_reqs,
        shared,
        &hashmap! {
            td::D_CRED_LABEL.to_string() =>
                api::SignatureAndRelatedData{ signature: d_sig.clone(), values: d_vals.clone(), accumulator_witnesses: d_wits.clone() },
            td::S_CRED_LABEL.to_string() =>
                api::SignatureAndRelatedData{ signature: s_sig.clone(), values: s_vals.clone(), accumulator_witnesses: s_wits.clone()},
        },
        proof_mode,
        None,
    )?;
    pp("w", &wr.warnings);
    pp("proof", &wr.data_for_verifier);
    Ok(wr)
}

fn do_verify_proof(
    vca_api      : &api::VcaApi,
    proof_reqs   : &HashMap<api::CredentialLabel, api::CredentialReqs>,
    shared       : &HashMap<api::SharedParamKey, api::SharedParamValue>,
    dfv          : api::DataForVerifier,
    decrypt_reqs : &HashMap<api::CredentialLabel,
                           HashMap<api::CredAttrIndex,
                                   HashMap<api::AuthorityLabel, api::DecryptRequest>>>,
    proof_mode              : ProofMode
) -> api::VCAResult<api::WarningsAndDecryptResponses> {
    let v = (*vca_api.verify_proof)(proof_reqs, shared, &dfv, decrypt_reqs, proof_mode, None)?;
    pp("verify", &v);
    Ok(v)
}
