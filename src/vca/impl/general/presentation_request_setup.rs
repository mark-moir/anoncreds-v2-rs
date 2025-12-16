// ----------------------------------------------------------------------------
use crate::vca::{Error, SerdeJsonError, VCAResult};
use crate::vca::r#impl::json::shared_params::{lookup_one_int, lookup_one_text};
use crate::vca::r#impl::json::util::decode_from_text;
use crate::vca::r#impl::util::{disjoint_vec_of_vecs, keys_vec_sorted, merge_maps, sort_by, TryCollectConcat};
use crate::vca::primitives::types::*;
use crate::vca::types::*;
// ----------------------------------------------------------------------------
use std::cmp::{min, Ordering};
use std::collections::{HashMap,HashSet};
use std::hash::Hash;
// ----------------------------------------------------------------------------

pub fn presentation_request_setup(
    pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    shared_params: &HashMap<SharedParamKey, SharedParamValue>,
    vals_to_reveal: &HashMap<CredentialLabel, HashMap<CredAttrIndex, DataValue>>,
    proof_mode: ProofMode,
) -> VCAResult<(
    Vec<ProofInstructionGeneral<ResolvedRequirement>>,
    EqualityReqs,
)> {
    let res_prf_insts = get_proof_instructions(shared_params, pres_reqs, vals_to_reveal, proof_mode)?;
    let eq_reqs = equality_reqs_from_pres_reqs_general(pres_reqs)?;
    if proof_mode != ProofMode::TestBackend {
        for eq_req in eq_reqs.clone() {
            check_equalities_have_same_claim_types::main(pres_reqs, shared_params, eq_req)?
        };
        // We could also check that values are the same if called by the prover, which would help to
        // catch mistakes by honest provers, but verification will fail if values differ anyway.
        // For this, we would need to have the caller optionally provide all attribute values, not
        // just disclosed ones.
    }
    Ok((res_prf_insts, eq_reqs))
}

// ----------------------------------------------------------------------------

mod check_equalities_have_same_claim_types {
    use super::*;
    use crate::issuer::IssuerPublic;
    use crate::str_vec_from;
    use crate::vca::r#impl::util::*;

    pub fn main(
        pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
        shared_params: &HashMap<SharedParamKey, SharedParamValue>,
        eq_req: EqualityReq) -> VCAResult<()> {
        let claim_types: Vec<ClaimType> = eq_req
            .iter()
            .map(|x| go(pres_reqs, shared_params, x.clone()))
            .collect::<VCAResult<_>>()?;
        match claim_types.first() {
            None => Ok(()),
            Some(ct) => {
                for ct1 in &claim_types[1..] {
                    if ct1 != ct {
                        return Err(Error::General(ic_semi(&str_vec_from!(
                            "checkEqualitiesHaveSameClaimTypes",
                            "multiple claim types",
                            format!("{claim_types:?}"),
                            format!("{eq_req:?}")))))
                    }
                };
                Ok(())
            }
        }
    }

    fn go (
        pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
        shared_params: &HashMap<SharedParamKey, SharedParamValue>,
        (c_lbl, a_idx): (CredentialLabel, CredAttrIndex)) -> VCAResult<ClaimType> {
        let issuer_lbl = lookup_throw_if_absent(&c_lbl, pres_reqs, Error::General,
                                                &["TODO ERROR 1".to_string()])?
            .signer_label.clone();
        let (SignerPublicData {signer_public_schema: schema, ..}) =
            decode_from_text(
                "Unable to decode IssuerPublic from shared parameters",
                lookup_one_text(&issuer_lbl, shared_params)?)?;
        lookup_throw_if_out_of_bounds(&schema, a_idx as usize, Error::General,
                                      &["TODO ERROR 2".to_string()]).copied()
    }
}


pub fn get_proof_instructions(
    sparms: &HashMap<SharedParamKey, SharedParamValue>,
    cred_reqs: &HashMap<CredentialLabel, CredentialReqs>,
    vals_to_reveal: &HashMap<CredentialLabel, HashMap<CredAttrIndex, DataValue>>,
    prf_mode: ProofMode,
) -> VCAResult<Vec<ProofInstructionGeneral<ResolvedRequirement>>> {
    let lkups = keys_vec_sorted(cred_reqs)
        .into_iter()
        .enumerate()
        .map(|(i, k)| (k.clone(), RelatedIndex(i as u64)))
        .collect::<HashMap<_, _>>();

    Ok(sort_by(
        merge_maps(cred_reqs.iter().collect(), vals_to_reveal.iter().collect())?
            .into_iter()
            .map(|(label, reqs_and_vals)|
                 get_proof_instructions_for_cred(sparms, &lkups, label, reqs_and_vals, prf_mode))
            .try_collect_concat()?,
        compare_prf_instrs,
    ))
}

fn compare_prf_instrs(
    pig1: &ProofInstructionGeneral<ResolvedRequirement>,
    pig2: &ProofInstructionGeneral<ResolvedRequirement>,
) -> Ordering {
    match (&pig1.requirement, &pig2.requirement) {
        (
            ResolvedRequirement::CredentialResolvedWrapper(_),
            ResolvedRequirement::CredentialResolvedWrapper(_),
        ) => pig1.cred_label.cmp(&pig2.cred_label),
        (ResolvedRequirement::CredentialResolvedWrapper(_), _) => Ordering::Less,
        (_, ResolvedRequirement::CredentialResolvedWrapper(_)) => Ordering::Greater,
        _ => pig1.cmp(pig2),
    }
}

// ----------------------------------------------------------------------------

pub const POK_OF_SIGNATURE_APPLIES_TO_ALL_ATTRIBUTES: u64 = 0;

fn get_proof_instructions_for_cred(
    sparms: &HashMap<SharedParamKey, SharedParamValue>,
    lkups: &HashMap<CredentialLabel, RelatedIndex>,
    c_lbl: &CredentialLabel,
    (
        CredentialReqs {
            signer_label,
            disclosed: Disclosed(requested_idxs),
            in_accum: InAccum(in_accum),
            not_in_accum: NotInAccum(not_in_accum),
            in_range: InRange(in_range),
            encrypted_for: EncryptedFor(encrypted_for),
            ..
        },
        vals_to_reveal,
    ): (&CredentialReqs, &HashMap<CredAttrIndex, DataValue>),
    prf_mode: ProofMode,
) -> VCAResult<Vec<ProofInstructionGeneral<ResolvedRequirement>>> {
    let cred_pi_idx = lkups.get(c_lbl).ok_or_else(|| {
        Error::General("get_proof_instructions_for_cred; INTERNAL ERROR".to_string())
    })?;
    let sig_res: ProofInstructionGeneral<ResolvedRequirement> = {
        if prf_mode != ProofMode::TestBackend {
            let revealed_idxs: HashSet<_> =
                vals_to_reveal.iter().map(|(i, _)| *i).collect();
            let requested_idxs: HashSet<_> =
                requested_idxs.iter().cloned().collect();
            if revealed_idxs != requested_idxs {
                return Err(Error::General(
                    format!("get_proof_instructions_for_cred; \
                             revealed values {:?} do not match \
                             indexes requested {:?} for {c_lbl}",
                            vals_to_reveal, requested_idxs)))
            }
        };
        let signer_public_data: SignerPublicData = decode_from_text(
            "Unable to decode IssuerPublic from shared parameters",
            lookup_one_text(signer_label, sparms)?)?;
        let schema = &signer_public_data.signer_public_schema;
        let reveal_vals_and_cts = vals_to_reveal
            .iter()
            .map(|(i, v)| -> VCAResult<_> {
                let ct = schema.get(*i as usize).ok_or_else(|| {
                    Error::General(format!(
                        "get_proof_instructions_for_cred; INTERNAL ERROR; {i}; {:?}",
                        &schema
                    ))
                })?;
                Ok((*i, (v.clone(), *ct)))
            })
            .collect::<VCAResult<HashMap<_, _>>>()?;
        Ok(ProofInstructionGeneral {
            cred_label: c_lbl.clone(),
            attr_idx_general: POK_OF_SIGNATURE_APPLIES_TO_ALL_ATTRIBUTES,
            related_pi_idx: *cred_pi_idx,
            requirement: ResolvedRequirement::CredentialResolvedWrapper(CredentialResolved {
                issuer_public: signer_public_data,
                rev_idxs_and_vals: reveal_vals_and_cts,
            }),
        })
    }?;

    let in_accum_res: Vec<ProofInstructionGeneral<ResolvedRequirement>> = in_accum
        .iter()
        .map(
            |InAccumInfo {
                 index,
                 accumulator_public_data_label,
                 membership_proving_key_label,
                 accumulator_label,
                 accumulator_seq_num_label
             }|
                -> VCAResult<ProofInstructionGeneral<ResolvedRequirement>> {
                let public_data: AccumulatorPublicData = decode_from_text(
                    "get_proof_instructions_for_cred",
                    lookup_one_text(accumulator_public_data_label, sparms)?)?;

                let mem_prv: MembershipProvingKey = decode_from_text(
                    "get_proof_instructions_for_cred",
                    lookup_one_text(membership_proving_key_label, sparms)?)?;

                let accumulator: Accumulator = decode_from_text(
                    "get_proof_instructions_for_cred",
                    lookup_one_text(accumulator_label, sparms)?)?;

                let seq_num = lookup_one_int(accumulator_seq_num_label, sparms)?;

                Ok(ProofInstructionGeneral {
                    cred_label: c_lbl.clone(),
                    attr_idx_general: *index,
                    related_pi_idx: *cred_pi_idx,
                    requirement: ResolvedRequirement::InAccumResolvedWrapper(InAccumResolved {
                        public_data,
                        mem_prv,
                        accumulator,
                        seq_num: *seq_num
                    }),
                })
            },
        )
        .collect::<VCAResult<Vec<_>>>()?;

    let in_range_res: Vec<ProofInstructionGeneral<ResolvedRequirement>> = in_range
        .iter()
        .map(
            |info| -> VCAResult<ProofInstructionGeneral<ResolvedRequirement>> {
                Ok(ProofInstructionGeneral {
                    cred_label: c_lbl.clone(),
                    attr_idx_general: info.index,
                    related_pi_idx: *cred_pi_idx,
                    requirement: ResolvedRequirement::InRangeResolvedWrapper(InRangeResolved {
                        min_val: *lookup_one_int(&info.min_label, sparms)?,
                        max_val: *lookup_one_int(&info.max_label, sparms)?,
                        proving_key: decode_from_text(
                            "get_proof_instructions_for_cred",
                            lookup_one_text(&info.range_proving_key_label, sparms)?,
                        )?,
                    }),
                })
            },
        )
        .collect::<VCAResult<Vec<_>>>()?;

    let en_f_res = encrypted_for
        .iter()
        .map(
            |IndexAndLabel {
                index: a_idx,
                label: auth_lbl,
            }| {
                let x = EncryptedForResolved {
                    auth_pub_label  : auth_lbl.to_string(),
                    auth_pub_data : decode_from_text(
                        "get_proof_instructions_for_cred",
                        lookup_one_text(auth_lbl, sparms)?)?
                };
                Ok(ProofInstructionGeneral {
                    cred_label: c_lbl.clone(),
                    attr_idx_general: *a_idx,
                    related_pi_idx: *cred_pi_idx,
                    requirement: ResolvedRequirement::EncryptedForResolvedWrapper(x),
                })
            },
        )
        .collect::<VCAResult<Vec<_>>>()?;

    Ok([vec![sig_res], in_accum_res, in_range_res, en_f_res].concat())
}

fn extract_eq_pairs_from_pres_reqs (
    pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
) -> VCAResult<EqualityReqs> {
    let mut all_eq_pairs: EqualityReqs = vec![];
    pres_reqs.iter().for_each(
        |(
            from_label,
            CredentialReqs {
                equal_to: EqualTo(equal_to),
                ..
            },
        )| {
            equal_to.iter().for_each(|EqInfo { from_index, to_label, to_index }| {
                all_eq_pairs.extend([vec![
                    (from_label.clone(), *from_index),
                    (to_label.clone(), *to_index),
                ]]);
            });
        },
    );
    Ok(all_eq_pairs)
}

// Ensure that, regardless of the order of `CredentialReqs` in `pres_reqs`,
// the `EqualityReqs` result is always in the same order.
// The order of `CredentialReqs` in `pres_reqs` may be different because of external input, such as:
// - provers and verifiers using equivalent but differently ordered `pres_reqs`
// - json de/serializers changing the order of items in maps
// When using AC2C, the prover and verifier must produce the same order of `EqualityReqs`
// regardless of the order of items in `pres_reqs`.
// If not, then the Merlin transcript check in verify fails.
fn equality_reqs_canonical_order (
    all_eq_pairs: &EqualityReqs,
) -> EqualityReqs {
    let mut all_eq_pairs_sorted = vec![];
    for v in all_eq_pairs.iter() {
        let mut v = v.clone().to_vec();
        v.sort();
        all_eq_pairs_sorted.push(v);
    }
    all_eq_pairs_sorted.sort();
    all_eq_pairs_sorted
}

/// Check that all Equality Reqs reference existing credentials, and attribute indices are in range
fn equality_reqs_from_pres_reqs_general(
    pres_reqs: &HashMap<CredentialLabel, CredentialReqs>,
) -> VCAResult<EqualityReqs> {
    // Get equality pairs from presentation requirements
    let mut all_eq_pairs =
        extract_eq_pairs_from_pres_reqs(pres_reqs)?;
    all_eq_pairs = disjoint_vec_of_vecs(all_eq_pairs);
    // Ensure all target credential labels are in map
    all_eq_pairs.iter().try_for_each(|eq_pairs| {
        eq_pairs.iter().try_for_each(|(x, _)| {
            pres_reqs
                .get(x)
                .ok_or(Error::General(
                    format!("equality_reqs_from_pres_reqs_general: Non-existent credential label {x}")))?;
            Ok(())
        })
    })?;
    // Put equality requirement in canoncial order
    Ok(equality_reqs_canonical_order(&all_eq_pairs))
}

pub fn is_cred_resolved(instr: &ProofInstructionGeneral<ResolvedRequirement>) -> bool {
    matches!(
        instr,
        ProofInstructionGeneral {
            requirement: ResolvedRequirement::CredentialResolvedWrapper(_),
            ..
        }
    )
}
