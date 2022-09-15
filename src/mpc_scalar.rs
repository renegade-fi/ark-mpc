//! Groups the definitions and trait implementations for a scalar value within an MPC network
#![allow(unused_doc_comments)]
mod macros;

use std::{rc::Rc, ops::{Add, Index, MulAssign, Mul, AddAssign, SubAssign, Sub, Neg}, iter::Product, borrow::Borrow};

use curve25519_dalek::scalar::Scalar;

use rand_core::{RngCore, CryptoRng};
use subtle::{ConstantTimeEq};

use crate::network::MpcNetwork;

#[allow(type_alias_bounds)]
pub type SharedNetwork<N: MpcNetwork> = Rc<N>;

/// Represents a scalar value allocated in an MPC network
#[derive(Clone, Debug)]
pub struct MpcScalar<N: MpcNetwork> {
    network: SharedNetwork<N>,
    value: Scalar,
}

impl<N: MpcNetwork> MpcScalar<N> {
    /// Create a scalar from a given u64
    pub fn from_u64(a: u64, network: SharedNetwork<N>) -> Self {
        Self { network, value: Scalar::from(a) }
    }

    /// Allocate an existing scalar in the network
    pub fn from_scalar(value: Scalar, network: SharedNetwork<N>) -> Self {
        Self { network, value }
    }

    /// Generate a random scalar
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R, network: SharedNetwork<N>) -> Self {
        Self { network, value: Scalar::random(rng) }
    }

    // Build a scalar from bytes
    macros::impl_delegated_wrapper!(from_bytes_mod_order, bytes, [u8; 32]);
    macros::impl_delegated_wrapper!(from_bytes_mod_order_wide, input, &[u8; 64]);
    pub fn from_canonical_bytes(bytes: [u8; 32], network: SharedNetwork<N>) -> Option<MpcScalar<N>> {
        Some(
            MpcScalar {
                network,
                value: Scalar::from_canonical_bytes(bytes)?,
            }
        )
    }
    macros::impl_delegated_wrapper!(from_bits, bytes, [u8; 32]);
    
    // Convert a scalar to bytes
    macros::impl_delegated!(to_bytes, self, [u8; 32]);
    macros::impl_delegated!(as_bytes, self, &[u8; 32]);
    // Compute the multiplicative inverse of the Scalar
    macros::impl_delegated_wrapper!(invert, self);
    // Invert a batch of scalars and return the product of inverses
    pub fn batch_invert(inputs: &mut [MpcScalar<N>]) -> MpcScalar<N> {
        let mut scalars: Vec<Scalar> = inputs.iter()
            .map(|mpc_scalar| mpc_scalar.value)
            .collect();

        MpcScalar {
            network: inputs[0].network.clone(),
            value: Scalar::batch_invert(&mut scalars)
        }
    }

    // Reduce the scalar mod l
    macros::impl_delegated_wrapper!(reduce, self);
    // Check whether the scalar is canonically represented mod l
    macros::impl_delegated!(is_canonical, self, bool);
    // Generate the additive identity
    macros::impl_delegated_wrapper!(zero);
    // Generate the multiplicative identity
    macros::impl_delegated_wrapper!(one);
}

/**
 * Generic trait implementations
 */

impl<N: MpcNetwork> PartialEq for MpcScalar<N> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value)
    }
}

impl<N: MpcNetwork> ConstantTimeEq for MpcScalar<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(&other.value)
    } 
}

impl<N: MpcNetwork> Index<usize> for MpcScalar<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.value.index(index)
    }
}


/**
 * Mul and variants for: borrowed, non-borrowed, and Scalar types
 */
macros::impl_arithmetic_assign_scalar!(MulAssign, mul_assign, *=, MpcScalar<N>);
macros::impl_arithmetic_assign_scalar!(MulAssign, mul_assign, *=, Scalar);
macros::impl_arithmetic_scalar!(Mul, mul, *, MpcScalar<N>);
macros::impl_arithmetic_scalar!(Mul, mul, *, Scalar);

/**
 * add and variants for: borrowed, non-borrowed, and scalar types
 */
macros::impl_arithmetic_assign_scalar!(AddAssign, add_assign, +=, MpcScalar<N>);
macros::impl_arithmetic_assign_scalar!(AddAssign, add_assign, +=, Scalar);
macros::impl_arithmetic_scalar!(Add, add, +, MpcScalar<N>);
macros::impl_arithmetic_scalar!(Add, add, +, Scalar);


/**
 * Sub and variants for: borrowed, non-borrowed, and scalar types
 */
macros::impl_arithmetic_assign_scalar!(SubAssign, sub_assign, -=, MpcScalar<N>);
macros::impl_arithmetic_assign_scalar!(SubAssign, sub_assign, -=, Scalar);
macros::impl_arithmetic_scalar!(Sub, sub, -, MpcScalar<N>);
macros::impl_arithmetic_scalar!(Sub, sub, -, Scalar);


impl<N: MpcNetwork> Neg for MpcScalar<N> {
    type Output = MpcScalar<N>; 
    fn neg(self) -> Self::Output {
        MpcScalar {
            network: self.network.clone(),
            value: self.value.neg()
        }
    }
}

impl<N: MpcNetwork, T: Borrow<MpcScalar<N>>> Product<T> for MpcScalar<N> {
    fn product<I: Iterator<Item = T>>(mut iter: I) -> Self {
        let first_elem = iter.next().unwrap();
        let network: SharedNetwork<N> = first_elem.borrow()
            .network
            .clone();
            
        iter.fold(MpcScalar::one(network), |acc, item| acc * item.borrow())
    }
}



#[cfg(test)]
mod test {
    use std::rc::Rc;

    use curve25519_dalek::scalar::Scalar;

    use crate::network::dummy_network::DummyMpcNetwork;

    use super::MpcScalar;

    #[test]
    fn test_zero() {
        let network = Rc::new(DummyMpcNetwork::new());
        let expected = MpcScalar::from_scalar(Scalar::zero(), network.clone());
        let zero = MpcScalar::zero(network);

        assert_eq!(zero, expected);
    }
}