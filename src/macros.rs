
/**
 * Implementation helper macros
 * In what follows, a "wrapped" type is the underlying type that arithmetic is actually
 * performed on. A "wrapper" type is the type that contains the "wrapped" type as an
 * element. E.g. RistrettoPoint is a "wrapped" type and MpcRistrettoPoint is a "wrapper"
 * type.
 */

/// Used to implement a funciton type that simple calls down to a Scalar function
/// i.e. calls a function on the underlying scalar 
macro_rules! impl_delegated {
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
    };

    // Static methods (no &self)
    ($function_name:ident, $base_type:ty, $return_type:ty) => {
        pub fn $function_name($($i:$j)*) -> $return_type {
            $base_type::$function_name($($i)*)
        }
    };
}

/// Used to implement a function type that calls an operation on a Scalar (returning another scalar)
/// and wraps the returned Scalar
/// Assumed to have a local trait bound of N: MpcNetwork + Send
macro_rules! impl_delegated_wrapper {
    // Static method, with public only
    ($base_type:ty, $function_name:ident) => {
        pub fn $function_name(network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
            Self {
                value: <$base_type>::$function_name(),
                visibility: Visibility::Public,
                network,
                beaver_source,
            }
        }
    };

    // Static methods with public_private 
    ($base_type:ty, $function_name:ident, $private_fn_name:ident, $with_visibility_function:ident) => {
        pub fn $function_name(network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
            Self::$with_visibility_function(Visibility::Public, network, beaver_source)
        }

        pub fn $private_fn_name(network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
            Self::$with_visibility_function(Visibility::Private, network, beaver_source)
        }

        fn $with_visibility_function(
            visibility: Visibility,
            network: SharedNetwork<N>, 
            beaver_source: BeaverSource<S>
        ) -> Self {
            Self {
                network,
                visibility,
                beaver_source,
                value: <$base_type>::$function_name()
            }
        }
    };

    // Static method single param
    ($base_type:ty, $function_name:ident, $with_visibility_function:ident, $param_name:ident, $param_type:ty) => {
        pub fn $function_name(
            $param_name: $param_type, 
            network: SharedNetwork<N>, 
            beaver_source: BeaverSource<S>,
        ) -> Self {
            Self::$with_visibility_function($param_name, Visibility::Public, network, beaver_source)
        }

        pub fn $with_visibility_function(
            $param_name: $param_type,
            visibility: Visibility,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>
        ) -> Self {
            Self {
                visibility,
                network,
                beaver_source,
                value: <$base_type>::$function_name($param_name),
            }
        }
    };
}

/// This macro handles wrapping an MPC value in an authenticated structure
macro_rules! impl_authenticated {
    // Static methods, public only
    ($base_type:ty, $function_name:ident) => {
        pub fn $function_name(key_share: MpcScalar<N, S>, network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
            Self {
                value: <$base_type>::$function_name(network, beaver_source),
                visibility: Visibility::Public,
                mac_share: None,
                key_share,
            }
        }
    };

    // Static methods (no &self)
    ($base_type:ty, $public_fn:ident, $private_fn:ident, $with_visibility_function:ident) => {
        pub fn $public_fn(key_share: MpcScalar<N, S>, network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
            Self::$with_visibility_function(Visibility::Public, key_share, network, beaver_source)
        }

        pub fn $private_fn(key_share: MpcScalar<N, S>, network: SharedNetwork<N>, beaver_source: BeaverSource<S>) -> Self {
            Self::$with_visibility_function(Visibility::Private, key_share, network, beaver_source)
        }

        fn $with_visibility_function(
            visibility: Visibility,
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>, 
            beaver_source: BeaverSource<S>
        ) -> Self {
            let value = <$base_type>::$with_visibility_function(Visibility::Public, network, beaver_source);
            Self {
                value,
                key_share,
                mac_share: None,
                visibility: Visibility::Public,
            } 
        }
    };

    // Static method single param
    ($base_type:ty, $public_fn:ident, $private_fn:ident, $with_visibility_function:ident, $param_type:ty) => {
        pub fn $public_fn(
            x: $param_type, 
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>, 
            beaver_source: BeaverSource<S>,
        ) -> Self {
            Self::$with_visibility_function(x, Visibility::Public, key_share, network, beaver_source)
        }

        pub fn $private_fn(
            x: $param_type,
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>,
        ) -> Self {
            Self::$with_visibility_function(x, Visibility::Private, key_share, network, beaver_source)
        }

        pub fn $with_visibility_function(
            x: $param_type,
            visibility: Visibility,
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>
        ) -> Self {
            Self {
                value: <$base_type>::$with_visibility_function(x, visibility, network, beaver_source),
                visibility,
                mac_share: None,
                key_share,
            }
        }
    };
}

/// Handles arithmetic assign ops for both wrapped and wrapper types
macro_rules! impl_arithmetic_assign {
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty) => {
        /// Default implementation
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs> for $lhs {
            fn $fn_name(&mut self, rhs: $rhs) {
                *self = &*self $op rhs
            }
        } 
    }
}

/// Handles arithmetic implementations between a wrapped type and its wrapper type 
macro_rules! impl_arithmetic_wrapped {
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $from_fn:ident, $rhs:ty) => {
        /// Default implementation
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs> for $lhs {
            type Output = $lhs;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                &self $op <$lhs>::$from_fn(rhs, self.network.clone(), self.beaver_source.clone())
            }
        }

        /// Implementation for borrowed reference types
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs> for &'a $lhs {
            type Output = $lhs;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                self $op <$lhs>::$from_fn(rhs, self.network.clone(), self.beaver_source.clone())
            }
        }
        
        /// Reverse implementation with wrapped type on the LHS
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$lhs> for $rhs {
            type Output = $lhs;

            fn $fn_name(self, rhs: $lhs) -> Self::Output {
                &rhs $op <$lhs>::$from_fn(self, rhs.network.clone(), rhs.beaver_source.clone())
            }
        }

        /// Reverse implementation with wrapped type on LHS and borrowed reference on RHS
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<&'a $lhs> for $rhs {
            type Output = $lhs;

            fn $fn_name(self, rhs: &'a $lhs) -> Self::Output {
                rhs $op <$lhs>::$from_fn(self, rhs.network.clone(), rhs.beaver_source.clone())
            }
        }
    };
}

/// Handles arithmetic between two wrapped types, assuming they both have a value() method
macro_rules! impl_arithmetic_wrapper {
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty) => {
        macros::impl_arithmetic_wrapper!($lhs, $trait, $fn_name, $op, $rhs, Output=$lhs);
    };
    
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty, Output=$out_type:ty) => {
        /// Default implementation
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs> for $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                &self $op &rhs
            }
        }

        /// Implementation for a borrowed reference on the right hand side
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<&'a $rhs> for $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: &'a $rhs) -> Self::Output {
                &self $op rhs
            }
        }

        /// Implementation for a borrowed reference on the left hand side
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs> for &'a $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                self $op &rhs
            }
        }
    }
}

macro_rules! impl_arithmetic_wrapped_authenticated {
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $from_fn:ident, $rhs:ty) => {
        /// Default implementation
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs> for $lhs {
            type Output = $lhs;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                &self $op <$lhs>::$from_fn(
                    rhs, 
                    self.key_share.clone(), 
                    self.network(), 
                    self.beaver_source()
                )
            }
        }

        /// Implementation for borrowed reference types
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$rhs> for &'a $lhs {
            type Output = $lhs;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                self $op <$lhs>::$from_fn(
                    rhs, 
                    self.key_share(), 
                    self.network(), 
                    self.beaver_source()
                )
            }
        }
        
        /// Reverse implementation with wrapped type on the LHS
        impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<$lhs> for $rhs {
            type Output = $lhs;

            fn $fn_name(self, rhs: $lhs) -> Self::Output {
                &rhs $op <$lhs>::$from_fn(
                    self, 
                    rhs.key_share.clone(), 
                    rhs.network(), 
                    rhs.beaver_source(),
                )
            }
        }

        /// Reverse implementation with wrapped type on LHS and borrowed reference on RHS
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> $trait<&'a $lhs> for $rhs {
            type Output = $lhs;

            fn $fn_name(self, rhs: &'a $lhs) -> Self::Output {
                rhs $op <$lhs>::$from_fn(
                    self, 
                    rhs.key_share(), 
                    rhs.network(), 
                    rhs.beaver_source()
                )
            }
        }
    };
}

// Exports
pub(crate) use impl_delegated;
pub(crate) use impl_delegated_wrapper;
pub(crate) use impl_authenticated;
pub(crate) use impl_arithmetic_assign;
pub(crate) use impl_arithmetic_wrapper;
pub(crate) use impl_arithmetic_wrapped;
pub(crate) use impl_arithmetic_wrapped_authenticated;