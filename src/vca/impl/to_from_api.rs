// ------------------------------------------------------------------------------
use crate::vca::{self, Error, SerdeCborError, SerdeJsonError, VCAResult};
// ------------------------------------------------------------------------------
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
// ------------------------------------------------------------------------------
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use serde_cbor::*;
use std::str;
// ------------------------------------------------------------------------------

pub trait VcaTryFrom<T>: Sized {
    fn vca_try_from(value: T) -> VCAResult<Self>;
}

// TODO: use this in more places, make a similar impl_vca_roundtrip_ark
// Convenience macro to generate symmetric JSON-based VcaTryFrom implementations
// for tuple-struct API wrappers that simply carry an opaque string.
#[macro_export]
macro_rules! impl_vca_roundtrip_json {
    ($native:ty => $api:path) => {
        impl $crate::vca::r#impl::to_from_api::VcaTryFrom<$native> for $api {
            fn vca_try_from(value: $native) -> $crate::vca::VCAResult<$api> {
                Ok($api($crate::vca::r#impl::to_from_api::to_opaque_json(&value)?))
            }
        }
        impl $crate::vca::r#impl::to_from_api::VcaTryFrom<&$native> for $api {
            fn vca_try_from(value: &$native) -> $crate::vca::VCAResult<$api> {
                Ok($api($crate::vca::r#impl::to_from_api::to_opaque_json(value)?))
            }
        }
        impl $crate::vca::r#impl::to_from_api::VcaTryFrom<&$api> for $native {
            fn vca_try_from(api: &$api) -> $crate::vca::VCAResult<$native> {
                $crate::vca::r#impl::to_from_api::from_opaque_json(&api.0)
            }
        }
    };
}

// Convenience macro to generate symmetric Ark-based VcaTryFrom implementations
// for tuple-struct API wrappers that simply carry an opaque string.
#[macro_export]
macro_rules! impl_vca_roundtrip_ark {
    ($native:ty => $api:path) => {
        impl $crate::vca::r#impl::to_from_api::VcaTryFrom<$native> for $api {
            fn vca_try_from(value: $native) -> $crate::vca::VCAResult<$api> {
                Ok($api($crate::vca::r#impl::to_from_api::to_opaque_ark(&value)?))
            }
        }
        impl $crate::vca::r#impl::to_from_api::VcaTryFrom<&$native> for $api {
            fn vca_try_from(value: &$native) -> $crate::vca::VCAResult<$api> {
                Ok($api($crate::vca::r#impl::to_from_api::to_opaque_ark(value)?))
            }
        }
        impl $crate::vca::r#impl::to_from_api::VcaTryFrom<&$api> for $native {
            fn vca_try_from(api: &$api) -> $crate::vca::VCAResult<$native> {
                $crate::vca::r#impl::to_from_api::from_opaque_ark(&api.0)
            }
        }
    };
}

pub fn to_api<FROM, API: VcaTryFrom<FROM>>(from: FROM) -> VCAResult<API>
{
    API::vca_try_from(from)
}

pub fn from_api<API, TO: VcaTryFrom<API>>(api: API) -> VCAResult<TO> {
    TO::vca_try_from(api)
}

// ------------------------------------------------------------------------------

pub fn to_opaque_json<T: Serialize>(t: &T) -> VCAResult<String> {
    let s = serde_json::to_string(t).map_err(|err| Error::SerdeError(SerdeJsonError(err)))?;
    Ok(to_opaque(s))
}

pub fn from_opaque_json<T: for<'de> Deserialize<'de>>(s: &str) -> VCAResult<T> {
    let s = from_opaque(s)?;
    serde_json::from_slice::<T>(s.as_bytes()).map_err(|e| Error::SerdeError(SerdeJsonError(e)))
}

// ------------------------------------------------------------------------------

// TODO: remove these when possible.  These should not be needed, but currently are, due to a
// serialization bug in bulletproofs; see tests/vca/range_proof_serialization_test.rs
pub fn to_opaque_cbor<T: Serialize>(t: &T) -> VCAResult<String> {
    let s = to_vec(t).map_err(|err| Error::SerdeCborError(SerdeCborError(err)))?;
    Ok(to_opaque(s))
}
pub fn from_opaque_cbor<T: for<'de> Deserialize<'de>>(s: &str) -> VCAResult<T> {
    let v = from_opaque_to_vec(s)?;
    let s = from_slice(&v).map_err(|err| Error::SerdeCborError(SerdeCborError(err)))?;
    Ok(s)
}

// ------------------------------------------------------------------------------

pub fn to_opaque_ark<T: CanonicalSerialize>(t: &T) -> VCAResult<String> {
    let s = ark_serialize(t)?;
    Ok(to_opaque(s))
}

pub fn from_opaque_ark<T: CanonicalDeserialize>(s: &str) -> VCAResult<T> {
    let v = from_opaque_to_vec(s)?;
    let t = ark_deserialize(&v)?;
    Ok(t)
}

// ------------------------------------------------------------------------------

fn to_opaque<S: AsRef<[u8]>>(s: S) -> String {
    BASE64_STANDARD.encode(s)
}

// pub for testing
pub fn from_opaque(s_b64: &str) -> VCAResult<String> {
    let s_bytes = BASE64_STANDARD
        .decode(s_b64)
        .map_err(Error::B64DecodeError)?;
    let s_utf8 = str::from_utf8(&s_bytes)
        .map_err(|err| Error::General(format!("from_opaque_json: {err}")))?;
    Ok(s_utf8.to_string())
}

fn from_opaque_to_vec(s_b64: &str) -> VCAResult<Vec<u8>> {
    let s_bytes = BASE64_STANDARD
        .decode(s_b64)
        .map_err(Error::B64DecodeError)?;
    Ok(s_bytes)
}

// ------------------------------------------------------------------------------

fn ark_serialize<T: CanonicalSerialize>(t: &T) -> VCAResult<Vec<u8>> {
    let mut serz = vec![];
    match CanonicalSerialize::serialize_compressed(t, &mut serz)
    {
        Ok(()) => Ok(serz),
        Err(e) => Err(Error::General(format!("ark_serialize: {e}")))
    }
}

fn  ark_deserialize<T: CanonicalDeserialize>(s: &[u8]) -> VCAResult<T> {
    match CanonicalDeserialize::deserialize_compressed(s)
    {
        Ok(deserz) => Ok(deserz),
        Err(e)     => Err(Error::General(format!("ark_deserialize: {e}")))
    }
}
