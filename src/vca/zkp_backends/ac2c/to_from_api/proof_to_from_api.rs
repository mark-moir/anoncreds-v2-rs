// ------------------------------------------------------------------------------
use crate::vca::r#impl::to_from_api::*;
use crate::vca::types::*;
use crate::vca::VCAResult;
// ------------------------------------------------------------------------------
use crate::knox::short_group_sig_core::short_group_traits::ShortGroupSignatureScheme;
use crate::prelude::Presentation;
use crate::presentation::GovernanceVerificationProof;
// ------------------------------------------------------------------------------

impl<S: ShortGroupSignatureScheme> VcaTryFrom<Presentation<S>> for Proof {
    fn vca_try_from(x: Presentation<S>) -> VCAResult<Proof> {
        Ok(Proof(to_opaque_cbor(&x)?))
    }
}

impl<S: ShortGroupSignatureScheme> VcaTryFrom<&Proof> for Presentation<S> {
    fn vca_try_from(x: &Proof) -> VCAResult<Presentation<S>> {
        from_opaque_cbor(&x.0)
    }
}

impl VcaTryFrom<DecryptionProof> for GovernanceVerificationProof {
    fn vca_try_from(x: DecryptionProof) -> VCAResult<GovernanceVerificationProof> {
        from_opaque_json(&x.0)
    }
}

impl VcaTryFrom<&GovernanceVerificationProof> for DecryptionProof {
    fn vca_try_from(x: &GovernanceVerificationProof) -> VCAResult<DecryptionProof> {
        Ok(DecryptionProof(to_opaque_json(x)?))
    }
}
