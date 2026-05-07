// ---------------------------------------------------------------------------
use crate::vca::api::VcaApi;
use crate::vca::crypto_interface::CryptoInterface;
use crate::vca::non_primitives::*;
use crate::vca::primitives::*;
use crate::vca::r#impl::general::proof::*;
use crate::vca::r#impl::general::signer::*;
use crate::vca::{Error, VCAResult};
// ---------------------------------------------------------------------------
use std::collections::HashMap;
use std::rc::Rc;
// ---------------------------------------------------------------------------

pub fn implement_vca_api_using(
    CryptoInterface {
        create_signer_data: csd,
        sign: ss,
        create_blind_signing_info: cbsi,
        sign_with_blinded_attributes: swba,
        unblind_blinded_signature: ubs,
        verify_signer_public_setup_data_correctness_proof: vspsdcp,
        verify_blind_signing_info_correctness_proof: vbsi_cp,
        verify_signature_correctness_proof: vscp,
        verify_blind_signature_correctness_proof: vbscp,
        create_range_proof_proving_key: crpk,
        get_range_proof_max_value: grpmv,
        create_authority_data: cauthd,
        create_accumulator_data: caccd,
        create_membership_proving_key: cmpk,
        create_accumulator_element: cae,
        accumulator_add_remove: aar,
        get_accumulator_witness: gaw,
        update_accumulator_witness: ucad,
        specific_prover: sp,
        specific_verifier: sv,
        specific_verify_decryption: svd,
    }: &CryptoInterface,
) -> VcaApi {
    VcaApi {
        create_signer_data: create_signer_data(csd.clone(), vspsdcp.clone()),
        sign: sign(ss.clone()),
        create_blind_signing_info: create_blind_signing_info(cbsi.clone(), vbsi_cp.clone()),
        sign_with_blinded_attributes: sign_with_blinded_attributes(swba.clone()),
        unblind_blinded_signature: unblind_blinded_signature(ubs.clone()),
        verify_signer_public_setup_data_correctness_proof: vspsdcp.clone(),
        verify_blind_signing_info_correctness_proof: vbsi_cp.clone(),
        verify_signature_correctness_proof: vscp.clone(),
        verify_blind_signature_correctness_proof: vbscp.clone(),
        create_range_proof_proving_key: crpk.clone(),
        get_range_proof_max_value: grpmv.clone(),
        create_authority_data: cauthd.clone(),
        create_accumulator_data: caccd.clone(),
        create_membership_proving_key: cmpk.clone(),
        create_accumulator_element: cae.clone(),
        accumulator_add_remove: aar.clone(),
        get_accumulator_witness: gaw.clone(),
        update_accumulator_witness: ucad.clone(),
        create_proof: create_proof(sp.clone()),
        verify_proof: verify_proof(sv.clone()),
        verify_decryption: verify_decryption(sv.clone(), svd.clone()),
    }
}
