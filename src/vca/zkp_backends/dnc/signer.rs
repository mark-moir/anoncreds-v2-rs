use crate::str_vec_from;
use crate::vca::r#impl::util::*;
// ------------------------------------------------------------------------------
use crate::vca::{Error, VCAResult};
use crate::vca::r#impl::to_from_api::*;
use crate::vca::interfaces::crypto_interface::*;
use crate::vca::zkp_backends::dnc::generate_frs::*;
use crate::vca::zkp_backends::dnc::reversible_encoding::text_to_field_element;
use crate::vca::zkp_backends::dnc::types::*;
// ------------------------------------------------------------------------------
use bbs_plus::prelude::KeypairG2;
use bbs_plus::prelude::PublicKeyG2;
use bbs_plus::prelude::SecretKey;
use bbs_plus::prelude::SignatureG1;
use bbs_plus::prelude::SignatureParamsG1;
use dock_crypto_utils::commitment::PedersenCommitmentKey;
use dock_crypto_utils::transcript::{new_merlin_transcript, Transcript};
// ------------------------------------------------------------------------------
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_std::rand::SeedableRng;
use ark_std::rand::rngs::StdRng;
use ark_std::UniformRand;
use blake2::Blake2b512;
// ------------------------------------------------------------------------------
use std::sync::Arc;
// ------------------------------------------------------------------------------

// ------------------------------------------------------------------------------

pub fn specific_create_signer_data() -> SpecificCreateSignerData {
    Arc::new(|rng_seed, schema, _| {
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let sp      = SignatureParamsG1::<Bls12_381>::generate_using_rng(&mut rng, (*schema).len() as u32);
        let kp      = KeypairG2::<Bls12_381>::generate_using_rng(&mut rng, &sp);
        let spsd    = to_api((sp, kp.public_key.clone()))?;
        Ok((spsd, to_api(kp.secret_key.clone())?))
    })
}

pub fn sign() -> SpecificSign {
    Arc::new(|rng_seed, vals, sd| {
        let SignerData { signer_public_data, signer_secret_data } = sd;
        let sk : SecretKeyBls12_381 = from_api(signer_secret_data)?;
        let SignerPublicData { signer_public_setup_data, signer_public_schema, .. } = *signer_public_data.clone();
        let (sp, _) : (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>) = from_api(&signer_public_setup_data)?;
        let frs = generate_frs_from_vals_and_cts(vals, &signer_public_schema, "sign")?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let s = SignatureG1::<Bls12_381>::new(&mut rng, &frs, &sk, &sp)
            .map_err(|e| Error::General(format!("sign, {:?}", e)))?;
        to_api(s)
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

/// Create a proof of knowledge of the blinder used to blind some messages.
fn create_blind_info_correctness_proof(
    spsd: &SignerPublicSetupData,
    messages: &[(usize, &Fr)],
    v_prime_blinder: &Fr,
    u_commitment: &G1Affine,
) -> VCAResult<BlindInfoCorrectnessProof> {
    let (sp, _): (SignatureParamsG1<Bls12_381>, PublicKeyG2<Bls12_381>) = from_api(spsd)?;
    // Sort messages by index for deterministic ordering
    let mut msgs = messages.to_vec();
    msgs.sort_by_key(|(idx, _)| *idx);

    // Randomness
    let mut rng = StdRng::from_entropy();
    let v_dash_tilde = Fr::rand(&mut rng);
    let m_tildes: Vec<Fr> = msgs.iter().map(|_| Fr::rand(&mut rng)).collect();

    // Commitment to randomness
    let mut u_tilde_proj = sp.h_0 * v_dash_tilde;
    for ((idx, _), m_tilde_i) in msgs.iter().zip(m_tildes.iter()) {
        u_tilde_proj += sp.h[*idx] * m_tilde_i;
    }
    let u_tilde = u_tilde_proj.into_affine();

    // Fiat-Shamir challenge
    let challenge =
        generate_challenge_for_blinding_info_correctness_proof(&sp, u_commitment, &u_tilde);

    // Responses
    let v_dash_cap = challenge * v_prime_blinder + v_dash_tilde;
    let m_caps: Vec<(usize, Fr)> = msgs
        .iter()
        .zip(m_tildes.iter())
        .map(|((idx, value), m_tilde)| (*idx, *m_tilde + challenge * *value))
        .collect();

    Ok(BlindInfoCorrectnessProof {
        u_tilde,
        v_dash_cap,
        m_caps,
    })
}

// The following is modeled after similar functionality implemented for anoncreds here:
//   https://github.com/anoncreds/anoncreds-clsignatures-rs/blob/5c74d040e842c25d8e9a05ca65dee6fb277a9be0/src/issuer.rs#L1018
// See comment above for create_blinding_info_correctness_proof.
/// Verify a proof of knowledge of the blinder used to blind some messages.
fn verify_blind_info_correctness_proof(
    sp: &SignatureParamsG1<Bls12_381>,
    u_commitment: &G1Affine,
    proof: &BlindInfoCorrectnessProof,
) -> VCAResult<()> {
    let challenge =
        generate_challenge_for_blinding_info_correctness_proof(sp, u_commitment, &proof.u_tilde);

    let u_cap = proof.m_caps.iter().fold(
        -(*u_commitment * challenge) + sp.h_0 * proof.v_dash_cap,
        |acc, (idx, m_cap)| acc + sp.h[*idx] * m_cap,
    );

    if u_cap != proof.u_tilde {
        return(Err(Error::General(
            "blind info proof verification failed".to_string()
        )))
    };
    Ok(())
}

pub fn specific_create_blind_signing_info() -> SpecificCreateBlindSigningInfo {
    Arc::new(|rng_seed, spsd, schema, blind_attrs| {
        let (sp, _) = from_api(spsd)?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let blinder = Fr::rand(&mut rng);
        let committed_messages_0: Vec<(usize,Fr)> =
            create_index_fr_pairs("create_blind_signing_info, DNC", blind_attrs, schema)?;
        let committed_messages = committed_messages_0
            .iter()
            .map(|(x,y)| (*x,y))
            .collect::<Vec<(usize,&Fr)>>();
        let blinding_info = sp.commit_to_messages(committed_messages.clone(), &blinder)
            .map_err(|e| Error::General(ic_semi(&str_vec_from!(
                "specific_create_blind_signing_info", format!("{e:?}")))))?;
        // Create and include PoK of blinder
        let blinding_info_correctness_proof = create_blind_info_correctness_proof(
            spsd,
            committed_messages.as_slice(),
            &blinder,
            &blinding_info,
        )?;
        let payload = BlindInfoForSignerPayload {
            blinding_info,
            blinding_info_correctness_proof,
        };
        Ok(BlindSigningInfo {
            blind_info_for_signer: to_api(payload)?,
            blinded_attributes: blind_attrs.to_vec(),
            info_for_unblinding: to_api(blinder)?,
        })
    })
}

pub fn specific_sign_with_blinded_attributes() -> SpecificSignWithBlindedAttributes {
    Arc::new(|rng_seed, schema, non_blinded_attrs, bifs, signer_public_setup_data, signer_secret_data | {
        let sk : SecretKeyBls12_381 = from_api(signer_secret_data)?;
        let (sp, _) : (SignatureParamsG1::<Bls12_381>, PublicKeyG2<Bls12_381>) =
            from_api(signer_public_setup_data)?;
        let mut rng = StdRng::seed_from_u64(rng_seed);
        let uncommitted_messages_0 =
            create_index_fr_pairs("specific_sign_with_blinded_attributes, DNC", non_blinded_attrs, schema)?;
        let uncommitted_messages = uncommitted_messages_0
            .iter()
            .map(|(x,y)| (*x,y))
            .collect::<BTreeMap<usize,&Fr>>();

        let BlindInfoForSignerPayload {
            blinding_info,
            blinding_info_correctness_proof,
        } = from_api(bifs)?;

        verify_blind_info_correctness_proof(
            &sp,
            &blinding_info,
            &blinding_info_correctness_proof,
        )?;

        let sig = SignatureG1::<Bls12_381>::new_with_committed_messages(
            &mut rng, &blinding_info, uncommitted_messages, &sk, &sp)
            .map_err(|e| Error::General(ic_semi(&str_vec_from!(
                "specific_sign_with_blinded_attributes",
                format!("{e:?}")))))?;
        to_api(sig)
    })
}

pub fn specific_unblind_blinded_signature(
) -> SpecificUnblindBlindedSignature {
    Arc::new(|_, _, blinded_sig, blinder_api| {
        let blinder = from_api(blinder_api)?;
        let blinded_sig: SignatureG1::<Bls12_381> = from_api(blinded_sig)?;
        to_api(blinded_sig.unblind(&blinder))
    })
}

fn create_index_fr_pair(
    s      : &str,
    schema : &[ClaimType],
    CredAttrIndexAndDataValue { index, value } : &CredAttrIndexAndDataValue,
) -> VCAResult<(usize, Fr)> {
    let ct = lookup_throw_if_out_of_bounds(
        schema, *index as usize, Error::General,
        &str_vec_from!(s,"createLabelFrPair", "DNC"))?;
    Ok((*index as usize, generate_fr_from_val_and_ct((ct, value))?))
}

fn create_index_fr_pairs(s: &str,
             attrs_and_vals: &[CredAttrIndexAndDataValue],
             schema: &[ClaimType]
) -> VCAResult<Vec<(usize,Fr)>> {
    attrs_and_vals
        .iter()
        .map(|cred_attr_index_and_data_value| {
            create_index_fr_pair(s, schema, cred_attr_index_and_data_value)
        })
        .collect::<Vec<VCAResult<(usize,Fr)>>>()
        .into_iter()
        .collect::<VCAResult<Vec<(usize,Fr)>>>()
}

fn generate_challenge_for_blinding_info_correctness_proof(
    sp: &SignatureParamsG1<Bls12_381>,
    u_commitment: &G1Affine,
    u_tilde: &G1Affine,
) -> Fr {
    let mut transcript = new_merlin_transcript(b"dnc_blind_info_correctness");
    transcript.append(b"signature params", sp);
    transcript.append(b"commitment to messages", u_commitment);
    transcript.append(b"commitment to randomness", u_tilde);
    transcript.challenge_scalar(b"challenge")
}

