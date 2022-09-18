
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
/// Assumed to have a local trait bound of N: MpcNetwork + Send
macro_rules! impl_delegated_wrapper {
    // Static methods (no &self)
    ($function_name:ident, $with_visibility_function:ident) => {
        pub fn $function_name(network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> MpcScalar<N, S> {
            Self::$with_visibility_function(Visibility::Public, network, beaver_source)
        }

        pub fn $with_visibility_function(
            visibility: Visibility,
            network: SharedNetwork<N>, 
            beaver_source: BeaverSource<S>
        ) -> MpcScalar<N, S> {
            MpcScalar {
                network,
                visibility,
                beaver_source,
                value: Scalar::$function_name()
            }
        }
    };

    // Static method single param
    ($function_name:ident, $with_visibility_function:ident, $param_name:ident, $param_type:ty) => {
        pub fn $function_name(
            $param_name: $param_type, 
            network: SharedNetwork<N>, 
            beaver_source: BeaverSource<S>,
        ) -> MpcScalar<N, S> {
            Self::$with_visibility_function($param_name, Visibility::Public, network, beaver_source)
        }

        pub fn $with_visibility_function(
            $param_name: $param_type,
            visibility: Visibility,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>
        ) -> MpcScalar<N, S> {
            MpcScalar {
                visibility,
                network,
                beaver_source,
                value: Scalar::$function_name($param_name),
            }
        }
    };
    
    // Instance methods (including &self)
    ($function_name:ident, $with_visibility_function:ident, self) => {
        pub fn $function_name(&self) -> MpcScalar<N, S> {
            self.$with_visibility_function(Visibility::Public)
        }

        pub fn $with_visibility_function(
            &self,
            visibility: Visibility
        ) -> MpcScalar<N, S> {
            MpcScalar {
                visibility,
                network: self.network.clone(),
                beaver_source: self.beaver_source.clone(),
                value: self.value.$function_name(),
            }
        }
    };

    // Mutable instance methods (including &mut self)
    ($function_name:ident, $with_visibility_function:ident, mut, self) => {
        pub fn $function_name(&mut self) -> MpcScalar<N> {
            MpcScalar {
                network: self.network,
                value: self.value.$function_name(),
            }
        }

        pub fn $with_visibility_function(&mut self, visibility: Visibility) -> MpcScalar<N, S> {
            MpcScalar {
                visibility,
                network: self.network.clone(),
                beaver_source: self.beaver_source.clone(),
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
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<Scalar> for MpcScalar<N, S> {
            fn $fn_name(&mut self, rhs: Scalar) {
                *self = &*self $op MpcScalar::from_scalar(rhs, self.network.clone(), self.beaver_source.clone())
            }
        }

        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<&'a Scalar> for MpcScalar<N, S> {
            fn $fn_name(&mut self, rhs: &'a Scalar) {
                *self = &*self $op MpcScalar::from_scalar(*rhs, self.network.clone(), self.beaver_source.clone())
            }
        }
    };

    ($trait:ident, $fn_name:ident, $op:tt, $rhs_type:ty) => {
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs_type> for MpcScalar<N, S> {
            fn $fn_name(&mut self, rhs: $rhs_type) {
                *self = &*self $op rhs
            }
        } 

        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<&'a $rhs_type> for MpcScalar<N, S> {
            fn $fn_name(&mut self, rhs: &'a $rhs_type) {
                *self = &*self $op rhs
            }
        }
    };
}

/// The arithmetic macro handles traits like Add, Sub, etc that produce an output
macro_rules! impl_arithmetic_scalar {
    ($trait:ident, $fn_name:ident, $op:tt, Scalar) => {
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<Scalar> for MpcScalar<N, S> {
            type Output = MpcScalar<N, S>;

            fn $fn_name(self, rhs: Scalar) -> Self::Output {
                &self $op MpcScalar::from_scalar(rhs, self.network.clone(), self.beaver_source.clone())
            }
        }

        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<Scalar> for &'a MpcScalar<N, S> {
            type Output = MpcScalar<N, S>;

            fn $fn_name(self, rhs: Scalar) -> Self::Output {
                self $op MpcScalar::from_scalar(rhs, self.network.clone(), self.beaver_source.clone())
            }
        }
    };

    ($trait:ident, $fn_name:ident, $op:tt, $rhs_type:ty) => {
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs_type> for MpcScalar<N, S> {
            type Output = MpcScalar<N, S>;

            fn $fn_name(self, rhs: $rhs_type) -> Self::Output {
                &self $op &rhs
            }
        }

        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<&'a $rhs_type> for MpcScalar<N, S> {
            type Output = MpcScalar<N, S>;

            fn $fn_name(self, rhs: &'a $rhs_type) -> Self::Output {
                &self $op rhs
            }
        }

        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs_type> for &'a MpcScalar<N, S> {
            type Output = MpcScalar<N, S>;

            fn $fn_name(self, rhs: $rhs_type) -> Self::Output {
                self $op &rhs
            }
        }
    };
}

// Exports
pub(crate) use impl_delegated;
pub(crate) use impl_delegated_wrapper;
pub(crate) use impl_arithmetic_assign_scalar;
pub(crate) use impl_arithmetic_scalar;