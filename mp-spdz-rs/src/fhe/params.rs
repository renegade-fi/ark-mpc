//! FHE setup parameters

use ark_ec::CurveGroup;
use ark_ff::{BigInteger, PrimeField};
use serde::{ser::SerializeSeq, Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;

use cxx::UniquePtr;

use crate::ffi::{bigint_from_be_bytes, fhe_params_from_rust_bytes, new_fhe_params, FHE_Params};

/// The default drowning security parameter
const DEFAULT_DROWN_SEC: i32 = 128;

/// A wrapper around the MP-SPDZ `FHE_Params` struct
pub struct BGVParams<C: CurveGroup> {
    /// The wrapped MP-SPDZ `FHE_Params`
    pub(crate) inner: UniquePtr<FHE_Params>,
    /// Phantom
    _phantom: PhantomData<C>,
}

impl<C: CurveGroup> Clone for BGVParams<C> {
    fn clone(&self) -> Self {
        self.as_ref().clone().into()
    }
}

impl<C: CurveGroup> From<UniquePtr<FHE_Params>> for BGVParams<C> {
    fn from(inner: UniquePtr<FHE_Params>) -> Self {
        Self { inner, _phantom: PhantomData }
    }
}

impl<C: CurveGroup> AsRef<FHE_Params> for BGVParams<C> {
    fn as_ref(&self) -> &FHE_Params {
        self.inner.as_ref().unwrap()
    }
}

impl<C: CurveGroup> BGVParams<C> {
    /// Create a new set of FHE parameters
    pub fn new(n_mults: u32) -> Self {
        let mut inner = new_fhe_params(n_mults as i32, DEFAULT_DROWN_SEC);

        // Generate the parameters
        let mut mod_bytes = C::ScalarField::MODULUS.to_bytes_be();
        let mod_bigint = unsafe { bigint_from_be_bytes(mod_bytes.as_mut_ptr(), mod_bytes.len()) };

        inner.pin_mut().param_generation_with_modulus(mod_bigint.as_ref().unwrap());
        Self { inner, _phantom: PhantomData }
    }

    /// Create a new set of FHE parameters that supports zero multiplications
    pub fn new_no_mults() -> Self {
        Self::new(0)
    }

    /// Get the number of plaintext slots the given parameters support
    pub fn plaintext_slots(&self) -> u32 {
        self.as_ref().n_plaintext_slots()
    }
}

impl<C: CurveGroup> Serialize for BGVParams<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes = self.as_ref().to_rust_bytes();
        let mut seq = serializer.serialize_seq(Some(bytes.len()))?;
        for byte in bytes.into_iter() {
            seq.serialize_element(&byte)?;
        }

        seq.end()
    }
}

impl<'de, C: CurveGroup> Deserialize<'de> for BGVParams<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let params = fhe_params_from_rust_bytes(&bytes);

        Ok(params.into())
    }
}

#[cfg(test)]
mod tests {
    use crate::fhe::params::BGVParams;
    use crate::TestCurve;

    /// Tests serialization and deserialization of the FHE parameters
    #[test]
    fn test_serde_params() {
        let params = BGVParams::<TestCurve>::new(1 /* n_mults */);

        let serialized = serde_json::to_vec(&params).unwrap();
        let deserialized: BGVParams<TestCurve> = serde_json::from_slice(&serialized).unwrap();

        // Compare by re-serializing
        let re_serialized = serde_json::to_vec(&deserialized).unwrap();
        assert_eq!(re_serialized, serialized);
    }
}
