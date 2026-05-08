use crate::str_vec_from;
use crate::vca::r#impl::util::*;
// ------------------------------------------------------------------------------
use crate::vca::interfaces::crypto_interface::*;
use crate::vca::interfaces::primitives::*;
use crate::vca::r#impl::to_from_api::*;
use crate::vca::zkp_backends::dnc::generate_frs::*;
use crate::vca::zkp_backends::dnc::reversible_encoding::text_to_field_element;
use crate::vca::zkp_backends::dnc::types::*;
use crate::vca::{Error, VCAResult};
// ------------------------------------------------------------------------------
use bbs_plus::prelude::KeypairG2;
use bbs_plus::prelude::PublicKeyG2;
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use bbs_plus::prelude::SignatureParamsG1;
use dock_crypto_utils::commitment::PedersenCommitmentKey;
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use ark_std::UniformRand;
use blake2::Blake2b512;
// ------------------------------------------------------------------------------
use crate::vca::zkp_backends::dnc::to_from_api::signer_to_from_api::{
    DncBlindSignatureCorrectnessProof, DncBlindSignatureWithProof, DncSignatureCorrectnessProof,
    DncSignatureWithProof, DncSignerPublicSetupData, DncSignerPublicSetupDataCorrectnessProof,
};
use proof_system::prelude::{MetaStatements, ProofSpec, Statement, Statements, Witness, Witnesses};
use proof_system::statement::ped_comm::PedersenCommitment as PedersenCommitmentStmt;
use std::sync::Arc;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

pub fn specific_create_signer_data() -> SpecificCreateSignerData {
    Arc::new(|rng_seed, schema, _| {
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let sp =
            SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, (*schema).len() as u32);
        let kp = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &sp);
        let spsd = to_api(DncSignerPublicSetupData {
            sig_params: sp,
            pk: kp.public_key.clone(),
            correctness_proof: DncSignerPublicSetupDataCorrectnessProof(b"TODO-proof".to_vec()),
        })?;
        Ok((spsd, to_api(kp.secret_key.clone())?))
    })
}

pub fn sign() -> SpecificSign {
    Arc::new(|rng_seed, vals, sd| {
        let SignerData {
            signer_public_data,
            signer_secret_data,
        } = sd;
        let sk: SecretKeyBls12_381 = from_api(signer_secret_data)?;
        let SignerPublicData {
            signer_public_setup_data,
            signer_public_schema,
            ..
        } = *signer_public_data.clone();
        let DncSignerPublicSetupData { sig_params: sp, .. } = from_api(&signer_public_setup_data)?;
        let frs = generate_frs_from_vals_and_cts(vals, &signer_public_schema, "sign")?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let s = SignatureG1::<Bls12_381>::new(&mut rng, &frs, &sk, &sp)
            .map_err(|e| Error::General(format!("sign, {:?}", e)))?;
        to_api(DncSignatureWithProof {
            signature: s,
            correctness_proof: DncSignatureCorrectnessProof("TODO-proof".to_string()),
        })
    })
}

// The following is modeled after similar functionality implemented for anoncreds here:
//
//   https://github.com/anoncreds/anoncreds-clsignatures-rs/blob/5c74d040e842c25d8e9a05ca65dee6fb277a9be0/src/prover.rs#L493
//
// to implement
//
//   https://anoncreds.github.io/anoncreds-spec/#the-blinded-link-secret-correctness-proof,
//
// which is what motivated this.  It therefore uses similar variable names for clarity VCA does not
// yet support committing to attributes, so only hidden blinded messages are supported here so far.

// TODO: This is a somewhat of an abstraction fail because it depends on knowing how the commitment
// was created, which is done in the bbs_plus crate.  Perhaps it should be in bbs_plus, rather than
// being left to the Issuer (see this comment:
//
//   https://github.com/docknetwork/crypto/blob/224f195bb8babc2d0de5256135120e0aca9fbd19/bbs_plus/src/signature.rs#L46
//
// Feedback from Lovesh.  Just do this via the proof system (which also solves the "abstraction fail"
// mentioned above).  See verify function here:
//
//   https://github.com/docknetwork/crypto-wasm-ts/blob/master/src/anonymous-credentials/blinded-credential-request.ts#L29
//
// and example workflow here:
//
//   https://github.com/docknetwork/crypto-wasm-ts/blob/master/src/anonymous-credentials/README.md#blinded-credentials

fn challenge_bytes_for(nonce: &str) -> Vec<u8> {
    format!("dnc_blind_info_correctness:{nonce}").into()
}


/// Create a proof of knowledge of the blinder used to blind some messages.
fn create_blind_info_correctness_proof(
    spsd: &SignerPublicSetupData,
    blinded_attributes: &[(usize, &Fr)],
    nonce: &str,
    v_prime_blinder: &Fr,
    u_commitment: &G1Affine,
) -> VCAResult<BlindInfoCorrectnessProof> {
    let (sp, _): (SignatureParamsG1<Bls12_381>, PublicKeyG2<Bls12_381>) = from_api(spsd)?;
    // Sort messages by index for deterministic ordering
    let mut msgs = blinded_attributes.to_vec();
    msgs.sort_by_key(|(idx, _)| *idx);

    // Build bases for just the blinded indices (plus h_0 for the blinder).
    let mut bases = msgs.iter().map(|(idx, _)| sp.h[*idx]).collect::<Vec<_>>();
    bases.push(sp.h_0);

    // Witness scalars: the blinded message values followed by the blinder.
    let mut scalars = msgs.iter().map(|(_, val)| **val).collect::<Vec<_>>();
    scalars.push(*v_prime_blinder);

    let mut statements = Statements::<Bls12_381>::new();
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        bases,
        *u_commitment,
    ));

    let mut witnesses = Witnesses::new();
    witnesses.add(Witness::PedersenCommitment(scalars));

    let proof_spec = ProofSpec::new(
        statements,
        MetaStatements::new(),
        vec![],
        Some(challenge_bytes_for(nonce)),
    );
    proof_spec.validate().map_err(|e| {
        Error::General(ic_semi(&str_vec_from!(
            "create_blind_info_correctness_proof",
            "proof_spec.validate",
            format!("{e:?}")
        )))
    })?;

    let mut rng = StdRng::from_entropy();
    let (proof, _) = ProofG1::new::<StdRng, Blake2b512>(
        &mut rng,
        proof_spec,
        witnesses,
        None,
        Default::default(),
    )
    .map_err(|e| {
        Error::General(ic_semi(&str_vec_from!(
            "create_blind_info_correctness_proof",
            "Proof::new",
            format!("{e:?}")
        )))
    })?;

    Ok(BlindInfoCorrectnessProof(proof))
}

/// Verify proof of knowledge of the blinder used to blind some messages.
fn verify_blind_info_correctness_proof(
    sp: &SignatureParamsG1<Bls12_381>,
    blinded_attr_idxs: &[CredAttrIndex],
    nonce: &str,
    u_commitment: &G1Affine,
    proof: &BlindInfoCorrectnessProof,
) -> VCAResult<()> {
    let mut bases = blinded_attr_idxs
        .iter()
        .map(|idx| sp.h[*idx as usize])
        .collect::<Vec<_>>();
    // Base for the blinder
    bases.push(sp.h_0);

    let mut statements = Statements::<Bls12_381>::new();
    statements.add(PedersenCommitmentStmt::new_statement_from_params(
        bases,
        *u_commitment,
    ));

    let proof_spec = ProofSpec::new(
        statements,
        MetaStatements::new(),
        vec![],
        Some(challenge_bytes_for(nonce)),
    );
    proof_spec.validate().map_err(|e| {
        Error::General(ic_semi(&str_vec_from!(
            "verify_blind_info_correctness_proof",
            "proof_spec.validate",
            format!("{e:?}")
        )))
    })?;

    let mut rng = StdRng::from_entropy();
    proof
        .0
        .clone()
        .verify::<StdRng, Blake2b512>(&mut rng, proof_spec, None, Default::default())
        .map_err(|e| {
            Error::General(ic_semi(&str_vec_from!(
                "verify_blind_info_correctness_proof",
                "Proof::verify",
                format!("{e:?}")
            )))
        })
}

pub fn specific_create_blind_signing_info() -> SpecificCreateBlindSigningInfo {
    Arc::new(|rng_seed, nonce, spsd, schema, blind_attrs| {
        let (sp, _) = from_api(spsd)?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let mut blinder = Fr::rand(&mut rng);

        let committed_messages_0: Vec<(usize, Fr)> =
            create_index_fr_pairs("create_blind_signing_info, DNC", blind_attrs, schema)?;
        let mut committed_messages = committed_messages_0
            .iter()
            .map(|(x, y)| (*x, y))
            .collect::<Vec<(usize, &Fr)>>();
        // in committed_messages
        let blinding_info = sp
            .commit_to_messages(committed_messages.clone(), &blinder)
            .map_err(|e| {
                Error::General(ic_semi(&str_vec_from!(
                    "specific_create_blind_signing_info",
                    format!("{e:?}")
                )))
            })?;
        // Create and include PoK of blinder
        let blinding_info_correctness_proof = create_blind_info_correctness_proof(
            spsd,
            committed_messages.as_slice(),
            nonce,
            &blinder,
            &blinding_info,
        )?;
        let blind_info = DncBlindInfoForSigner {
            blinding_info,
            blinding_info_correctness_proof,
        };
        Ok(BlindSigningInfo {
            blind_info_for_signer: to_api(blind_info)?,
            blinded_attributes: blind_attrs.to_vec(),
            info_for_unblinding: to_api(blinder)?,
        })
    })
}

pub fn specific_sign_with_blinded_attributes() -> SpecificSignWithBlindedAttributes {
    Arc::new(
        |rng_seed,
         schema,
         non_blinded_attrs,
         bifs,
         signer_public_setup_data,
         signer_secret_data| {
            let sk: SecretKeyBls12_381 = from_api(signer_secret_data)?;
            let (sp, _): (SignatureParamsG1<Bls12_381>, PublicKeyG2<Bls12_381>) =
                from_api(signer_public_setup_data)?;
            let mut rng = StdRng::seed_from_u64(rng_seed);
            let uncommitted_messages_0 = create_index_fr_pairs(
                "specific_sign_with_blinded_attributes, DNC",
                non_blinded_attrs,
                schema,
            )?;
            let uncommitted_messages = uncommitted_messages_0
                .iter()
                .map(|(x, y)| (*x, y))
                .collect::<BTreeMap<usize, &Fr>>();

            let DncBlindInfoForSigner { blinding_info, .. } = from_api(bifs)?;

            let sig = SignatureG1::<Bls12_381>::new_with_committed_messages(
                &mut rng,
                &blinding_info,
                uncommitted_messages,
                &sk,
                &sp,
            )
            .map_err(|e| {
                Error::General(ic_semi(&str_vec_from!(
                    "specific_sign_with_blinded_attributes",
                    format!("{e:?}")
                )))
            })?;
            // TODO: implement DncBlindSignatureCorrectnessProof
            to_api(DncBlindSignatureWithProof {
                blind_signature: sig,
                correctness_proof: DncBlindSignatureCorrectnessProof("TODO-proof".to_string()),
            })
        },
    )
}

pub fn specific_unblind_blinded_signature() -> SpecificUnblindBlindedSignature {
    Arc::new(|_, _, blinded_sig, blinder_api| {
        let blinder = from_api(blinder_api)?;
        let DncBlindSignatureWithProof {
            blind_signature, ..
        } = from_api(blinded_sig)?;
        to_api(DncSignatureWithProof {
            signature: blind_signature.unblind(&blinder),
            correctness_proof: DncSignatureCorrectnessProof("TODO-proof".to_string()),
        })
    })
}

fn create_index_fr_pair(
    s: &str,
    schema: &[ClaimType],
    CredAttrIndexAndDataValue { index, value }: &CredAttrIndexAndDataValue,
) -> VCAResult<(usize, Fr)> {
    let ct = lookup_throw_if_out_of_bounds(
        schema,
        *index as usize,
        Error::General,
        &str_vec_from!(s, "createLabelFrPair", "DNC"),
    )?;
    Ok((*index as usize, generate_fr_from_val_and_ct((ct, value))?))
}

fn create_index_fr_pairs(
    s: &str,
    attrs_and_vals: &[CredAttrIndexAndDataValue],
    schema: &[ClaimType],
) -> VCAResult<Vec<(usize, Fr)>> {
    attrs_and_vals
        .iter()
        .map(|cred_attr_index_and_data_value| {
            create_index_fr_pair(s, schema, cred_attr_index_and_data_value)
        })
        .collect::<Vec<VCAResult<(usize, Fr)>>>()
        .into_iter()
        .collect::<VCAResult<Vec<(usize, Fr)>>>()
}

// ---------------------------------------------------------------------------
// Correctness proof verification stubs (placeholder: always Verified)

pub fn verify_signer_public_setup_data_correctness_proof(
) -> VerifySignerPublicSetupDataCorrectnessProof {
    Arc::new(|_| {
        // TODO: implement correctness proof verification instead of always returning Verified
        Ok(())
    })
}

pub fn verify_blind_signing_info_correctness_proof() -> VerifyBlindSigningInfoCorrectnessProof {
    Arc::new(
        |signer_public_setup_data, blind_attr_idxs, nonce, blind_info_for_signer| {
            // Convert inputs back to concrete types
            let DncSignerPublicSetupData { sig_params: sp, .. } =
                from_api(signer_public_setup_data)?;
            let DncBlindInfoForSigner {
                blinding_info,
                blinding_info_correctness_proof,
            } = from_api(blind_info_for_signer)?;

            match verify_blind_info_correctness_proof(
                &sp,
                blind_attr_idxs,
                nonce,
                &blinding_info,
                &blinding_info_correctness_proof,
            ) {
                Ok(()) => Ok(()),
                Err(err) => Err(Error::General(ic_semi(&str_vec_from!(
                    "verify_blind_signing_correctness_proof",
                    "blind signing correctness proof verification failed",
                    format!("{err:?}")
                )))),
            }
        },
    )
}

pub fn verify_signature_correctness_proof() -> VerifySignatureCorrectnessProof {
    Arc::new(|_, _| {
        // TODO: implement correctness proof verification instead of always returning Verified
        Ok(())
    })
}

pub fn verify_blind_signature_correctness_proof() -> VerifyBlindSignatureCorrectnessProof {
    Arc::new(|_, _| {
        // TODO: implement correctness proof verification instead of always returning Verified
        Ok(())
    })
}
