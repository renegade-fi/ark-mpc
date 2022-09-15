//! Groups the definitions and trait implementations for a scalar value within an MPC network

use std::{rc::Rc, ops::{Add, Index, MulAssign, Mul, AddAssign, SubAssign, Sub, Neg}};

use curve25519_dalek::scalar::Scalar;

use rand_core::{RngCore, CryptoRng};
use subtle::{ConstantTimeEq};

use crate::network::MPCNetwork;

#[allow(type_alias_bounds)]
pub type SharedNetwork<N: MPCNetwork> = Rc<N>;

/**
 * Implementation helper macros
 */

/// Used to implement a funciton type that simple calls down to a Scalar function
/// i.e. calls a function on the underlying scalar 
macro_rules! impl_delegated {
    // Static methods (no &self)
    ($function_name:ident, $return_type:ty) => {
        pub fn $function_name($($i:$j)*) -> $return_type {
            Scalar::$function_name($($i)*)
        }
    };

    // Instance methods (&self)
    ($function_name:ident, self, $return_type:ty) => {
        pub fn $function_name(&self) -> $return_type {
            self.value.$function_name()
        }
    };

    // Mutable instance methods (&mut self)
    ($function_name:ident, mut, self, $return_type:ty) => {
        pub fn $function_name(&mut self) -> $return_type {
            self.value.$function_name()
        }
    }
}

/// Used to implement a function type that calls an operation on a Scalar (returning another scalar)
/// and wraps the returned Scalar
/// Assumed to have a local trait bound of N: MpcNetwork
macro_rules! impl_delegated_wrapper {
    // Static methods (no &self)
    ($function_name:ident) => {
        pub fn $function_name(network: SharedNetwork<N>) -> MpcScalar<N> {
            MpcScalar {
                network: network.clone(),
                value: Scalar::$function_name()
            }
        }
    };

    // Static method single param
    ($function_name:ident, $param_name:ident, $param_type:ty) => {
        pub fn $function_name($param_name: $param_type, network: SharedNetwork<N>) -> MpcScalar<N> {
            MpcScalar {
                network: network.clone(),
                value: Scalar::$function_name($param_name),
            }
        }
    };
    
    // Instance methods (including &self)
    ($function_name:ident, self) => {
        pub fn $function_name(&self) -> MpcScalar<N> {
            MpcScalar {
                network: self.network.clone(),
                value: self.value.$function_name(),
            }
        }
    };

    // Mutable instance methods (including &mut self)
    ($function_name:ident, mut, self) => {
        pub fn $function_name(&mut self) -> MpcScalar<N> {
            MpcScalar {
                network: self.network.clone(),
                value: self.value.$function_name(),
            }
        }
    }
}

/// Represents a scalar value allocated in an MPC network
#[derive(Clone, Debug)]
pub struct MpcScalar<N: MPCNetwork> {
    network: SharedNetwork<N>,
    value: Scalar,
}

impl<N: MPCNetwork> MpcScalar<N> {
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
    impl_delegated_wrapper!(from_bytes_mod_order, bytes, [u8; 32]);
    impl_delegated_wrapper!(from_bytes_mod_order_wide, input, &[u8; 64]);
    pub fn from_canonical_bytes(bytes: [u8; 32], network: SharedNetwork<N>) -> Option<MpcScalar<N>> {
        Some(
            MpcScalar {
                network,
                value: Scalar::from_canonical_bytes(bytes)?,
            }
        )
    }
    impl_delegated_wrapper!(from_bits, bytes, [u8; 32]);
    
    // Convert a scalar to bytes
    impl_delegated!(to_bytes, self, [u8; 32]);
    impl_delegated!(as_bytes, self, &[u8; 32]);
    // Compute the multiplicative inverse of the Scalar
    impl_delegated_wrapper!(invert, self);
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
    impl_delegated_wrapper!(reduce, self);
    // Check whether the scalar is canonically represented mod l
    impl_delegated!(is_canonical, self, bool);
    // Generate the additive identity
    impl_delegated_wrapper!(zero);
    // Generate the multiplicative identity
    impl_delegated_wrapper!(one);
}

/**
 * Generic trait implementations
 */

impl<N: MPCNetwork> PartialEq for MpcScalar<N> {
    fn eq(&self, other: &Self) -> bool {
        self.value.eq(&other.value)
    }
}

impl<N: MPCNetwork> ConstantTimeEq for MpcScalar<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value.ct_eq(&other.value)
    } 
}

impl<N: MPCNetwork> Index<usize> for MpcScalar<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        self.value.index(index)
    }
}


/**
 * Arithmetic ops
 */

impl<N: MPCNetwork> MulAssign<MpcScalar<N>> for MpcScalar<N> {
    fn mul_assign(&mut self, rhs: MpcScalar<N>) {
        self.value *= rhs.value
    }
}

impl<N: MPCNetwork> Mul<MpcScalar<N>> for MpcScalar<N> {
    type Output = MpcScalar<N>;

    fn mul(self, rhs: MpcScalar<N>) -> Self::Output {
        MpcScalar {
            network: self.network.clone(),
            value: self.value * rhs.value
        }
    }
}

impl<N: MPCNetwork> AddAssign<MpcScalar<N>> for MpcScalar<N> {
    fn add_assign(&mut self, rhs: MpcScalar<N>) {
        self.value += rhs.value
    }
}

impl<N: MPCNetwork> Add<MpcScalar<N>> for MpcScalar<N> {
    type Output = MpcScalar<N>;

    fn add(self, rhs: MpcScalar<N>) -> Self::Output {
        MpcScalar {
            network: self.network.clone(),
            value: self.value + rhs.value
        }
    }
}

/// Add with a plain scalar, automatically allocate in the network
impl<N: MPCNetwork> Add<Scalar> for MpcScalar<N> {
    type Output = MpcScalar<N>;

    fn add(self, rhs: Scalar) -> Self::Output {
        MpcScalar {
            network: self.network.clone(),
            value: self.value + rhs
        }
    }
}

impl<N: MPCNetwork> SubAssign<MpcScalar<N>> for MpcScalar<N> {
    fn sub_assign(&mut self, rhs: MpcScalar<N>) {
        self.value -= rhs.value
    }
}

impl<N: MPCNetwork> Sub<MpcScalar<N>> for MpcScalar<N> {
    type Output = MpcScalar<N>; 

    fn sub(self, rhs: MpcScalar<N>) -> Self::Output {
        MpcScalar {
            network: self.network.clone(),
            value: self.value - rhs.value
        }
    }
}

impl<N: MPCNetwork> Neg for MpcScalar<N> {
    type Output = MpcScalar<N>; 
    fn neg(self) -> Self::Output {
        MpcScalar {
            network: self.network.clone(),
            value: self.value.neg()
        }
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