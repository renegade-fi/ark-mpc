
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

/// Helper macro for implementing arithmetic ops on underlying types, combinations of their borrows
/// and against a right hand side of a raw Scalar.
/// The assign macro handles traits like AddAssign, SubAssign, etc
macro_rules! impl_arithmetic_assign_scalar {
    ($trait:ident, $fn_name:ident, $op:tt, Scalar) => {
        impl<N: MpcNetwork> $trait<Scalar> for MpcScalar<N> {
            fn $fn_name(&mut self, rhs: Scalar) {
                self.value $op rhs
            }
        }

        impl<'a, N: MpcNetwork> $trait<&'a Scalar> for MpcScalar<N> {
            fn $fn_name(&mut self, rhs: &'a Scalar) {
                self.value $op rhs
            }
        }
    };

    ($trait:ident, $fn_name:ident, $op:tt, $rhs_type:ty) => {
        impl<N: MpcNetwork> $trait<$rhs_type> for MpcScalar<N> {
            fn $fn_name(&mut self, rhs: $rhs_type) {
                self.value $op rhs.value
            }
        } 

        impl<'a, N: MpcNetwork> $trait<&'a $rhs_type> for MpcScalar<N> {
            fn $fn_name(&mut self, rhs: &'a $rhs_type) {
                self.value $op rhs.value
            }
        }
    };
}

/// The arithmetic macro handles traits like Add, Sub, etc that produce an output
macro_rules! impl_arithmetic_scalar {
    ($trait:ident, $fn_name:ident, $op:tt, Scalar) => {
        impl<N: MpcNetwork> $trait<Scalar> for MpcScalar<N> {
            type Output = MpcScalar<N>;

            fn $fn_name(self, rhs: Scalar) -> Self::Output {
                MpcScalar {
                    network: self.network.clone(),
                    value: self.value $op rhs
                }
            }
        }

        impl<'a, N: MpcNetwork> $trait<&'a Scalar> for MpcScalar<N> {
            type Output = MpcScalar<N>;

            fn $fn_name(self, rhs: &'a Scalar) -> Self::Output {
                MpcScalar {
                    network: self.network.clone(),
                    value: self.value $op rhs
                }
            }
        }

        impl<'a, N: MpcNetwork> $trait<Scalar> for &'a MpcScalar<N> {
            type Output = MpcScalar<N>;

            fn $fn_name(self, rhs: Scalar) -> Self::Output {
                MpcScalar {
                    network: self.network.clone(),
                    value: self.value $op rhs
                }
            }
        }
    };

    ($trait:ident, $fn_name:ident, $op:tt, $rhs_type:ty) => {
        impl<N: MpcNetwork> $trait<$rhs_type> for MpcScalar<N> {
            type Output = MpcScalar<N>;

            fn $fn_name(self, rhs: $rhs_type) -> Self::Output {
                MpcScalar {
                    network: self.network.clone(),
                    value: self.value $op rhs.value
                }
            }
        }

        impl<'a, N: MpcNetwork> $trait<&'a $rhs_type> for MpcScalar<N> {
            type Output = MpcScalar<N>;

            fn $fn_name(self, rhs: &'a $rhs_type) -> Self::Output {
                MpcScalar {
                    network: self.network.clone(),
                    value: self.value $op rhs.value
                }
            }
        }

        impl<'a, N: MpcNetwork> $trait<$rhs_type> for &'a MpcScalar<N> {
            type Output = MpcScalar<N>;

            fn $fn_name(self, rhs: $rhs_type) -> Self::Output {
                MpcScalar {
                    network: self.network.clone(),
                    value: self.value $op rhs.value
                }
            }
        }
    };
}

// Exports
pub(crate) use impl_delegated;
pub(crate) use impl_delegated_wrapper;
pub(crate) use impl_arithmetic_assign_scalar;
pub(crate) use impl_arithmetic_scalar;