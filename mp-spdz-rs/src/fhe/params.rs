//! FHE setup parameters

use ark_ec::CurveGroup;
use ark_mpc::algebra::Scalar;
use std::marker::PhantomData;

use cxx::UniquePtr;

use crate::ffi::{new_fhe_params, FHE_Params};

/// The default drowning security parameter
const DEFAULT_DROWN_SEC: i32 = 128;

/// A wrapper around the MP-SPDZ `FHE_Params` struct
pub struct BGVParams<C: CurveGroup> {
    /// The wrapped MP-SPDZ `FHE_Params`
    pub(crate) inner: UniquePtr<FHE_Params>,
    /// Phantom
    _phantom: PhantomData<C>,
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
        let bits = Scalar::<C>::bit_length() as i32;
        inner.pin_mut().basic_generation_mod_prime(bits);

        Self { inner, _phantom: PhantomData }
    }

    /// Create a new set of FHE parameters that supports zero multiplications
    pub fn new_no_mults() -> Self {
        Self::new(0)
    }
}
