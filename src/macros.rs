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
            beaver_source: BeaverSource<S>,
        ) -> Self {
            Self {
                network,
                visibility,
                beaver_source,
                value: <$base_type>::$function_name(),
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
            beaver_source: BeaverSource<S>,
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
        pub fn $function_name(
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>,
        ) -> Self {
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
        pub fn $public_fn(
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>,
        ) -> Self {
            Self::$with_visibility_function(Visibility::Public, key_share, network, beaver_source)
        }

        pub fn $private_fn(
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>,
        ) -> Self {
            Self::$with_visibility_function(Visibility::Private, key_share, network, beaver_source)
        }

        fn $with_visibility_function(
            visibility: Visibility,
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>,
        ) -> Self {
            let value =
                <$base_type>::$with_visibility_function(Visibility::Public, network, beaver_source);
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
            Self::$with_visibility_function(
                x,
                Visibility::Public,
                key_share,
                network,
                beaver_source,
            )
        }

        pub fn $private_fn(
            x: $param_type,
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>,
        ) -> Self {
            Self::$with_visibility_function(
                x,
                Visibility::Private,
                key_share,
                network,
                beaver_source,
            )
        }

        pub fn $with_visibility_function(
            x: $param_type,
            visibility: Visibility,
            key_share: MpcScalar<N, S>,
            network: SharedNetwork<N>,
            beaver_source: BeaverSource<S>,
        ) -> Self {
            Self {
                value: <$base_type>::$with_visibility_function(
                    x,
                    visibility,
                    network,
                    beaver_source,
                ),
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
        impl<N: MpcNetwork + Send, S: SharedValueSource> $trait<$rhs> for $lhs {
            fn $fn_name(&mut self, rhs: $rhs) {
                *self = &*self $op &rhs;
            }
        }

        /// Implementation on reference types
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource> $trait<&'a $rhs> for $lhs {
            fn $fn_name(&mut self, rhs: &'a $rhs) {
                *self = &*self $op rhs
            }
        }
    }
}

/// Assumes that an implementation exists for the case in which both values are borrowed
macro_rules! impl_operator_variants {
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty) => {
        macros::impl_operator_variants!($lhs, $trait, $fn_name, $op, $rhs, Output=$lhs);
    };

    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty, Output=$out_type:ty) => {
        /// LHS borrowed, RHS non-borrowed
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource> $trait<$rhs> for &'a $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                self $op &rhs
            }
        }

        /// LHS non-borrowed, RHS borrowed
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource> $trait<&'a $rhs> for $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: &'a $rhs) -> Self::Output {
                &self $op rhs
            }
        }

        /// LHS non-borrowed, RHS non-borrowed
        impl<N: MpcNetwork + Send, S: SharedValueSource> $trait<$rhs> for $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                &self $op &rhs
            }
        }
    }
}

/// This macro helps in defining arithmetic on wrapped types
///
/// The high level approach here is as follows:
///     1. Define an implementation of the operation on references of the wrapper and contained types
///        that converts the contained type to the wrapper type.
///     2. Call out to `impl_operator_variants` to implement borrow-variants for the operation
///     3. Do 1-2 in the reverse order, i.e. with LHS and RHS types switched
macro_rules! impl_wrapper_type {
    // A helper to call the macro cases below with the default output type equal to the wrapper
    ($wrapper_type:ty, $wrapped_type:ty, $from_fn:expr, $trait:ident, $fn_name:ident, $op:tt, authenticated=false) => {
        macros::impl_wrapper_type!(
            $wrapper_type,
            $wrapped_type,
            $from_fn,
            $trait,
            $fn_name,
            $op,
            Output=$wrapper_type,
            authenticated=false
        );
    };

    // The same style helper as above, but for authenticated wrapper types
    ($wrapper_type:ty, $wrapped_type:ty, $from_fn:expr, $trait:ident, $fn_name:ident, $op:tt, authenticated=true) => {
        macros::impl_wrapper_type!(
            $wrapper_type,
            $wrapped_type,
            $from_fn,
            $trait,
            $fn_name,
            $op,
            Output=$wrapper_type,
            authenticated=true
        );
    };

    // Wrapper macro that defines an arithmetic wrapper for an unauthenticated wrapper type
    ($wrapper_type:ty, $wrapped_type:ty, $from_fn:expr, $trait:ident, $fn_name:ident, $op:tt, Output=$output_type:ty, authenticated=false) => {
        // Base implementation with wrapper on the LHS and wrapped type on the RHS
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource> $trait<&'a $wrapped_type>
            for &'a $wrapper_type
        {
            // Output is always the wrapper type
            type Output = $output_type;

            fn $fn_name(self, rhs: &'a $wrapped_type) -> Self::Output {
                self $op $from_fn(rhs.clone(), self.network.clone(), self.beaver_source.clone())
            }
        }

        // Implement variants for borrowed and non-borrowed arguments
        macros::impl_operator_variants!($wrapper_type, $trait, $fn_name, $op, $wrapped_type, Output=$output_type);

        // Base implementation with wrapped type on the LHS and wrapper on the RHS
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource> $trait<&'a $wrapper_type> for &'a $wrapped_type {
            // Output is always the wrapper type
            type Output = $output_type;

            fn $fn_name(self, rhs: &'a $wrapper_type) -> Self::Output {
                $from_fn(self.clone(), rhs.network.clone(), rhs.beaver_source.clone()) $op rhs
            }
        }

        // Implement variants for borrowed and non-borrowed arguments
        macros::impl_operator_variants!($wrapped_type, $trait, $fn_name, $op, $wrapper_type, Output=$output_type);
    };

    // Wrapper macro that defines an arithmetic wrapper for an authenticated wrapper type
    ($wrapper_type:ty, $wrapped_type:ty, $from_fn:expr, $trait:ident, $fn_name:ident, $op:tt, Output=$output_type:ty, authenticated=true) => {
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource> $trait<&'a $wrapped_type>
            for &'a $wrapper_type
        {
            // Output is always the wrapper type
            type Output = $output_type;

            fn $fn_name(self, rhs: &'a $wrapped_type) -> Self::Output {
                self $op $from_fn(rhs.clone(), self.key_share(), self.network(), self.beaver_source())
            }
        }

        // Implement variants for borrowed and non-borrowed arguments
        macros::impl_operator_variants!($wrapper_type, $trait, $fn_name, $op, $wrapped_type, Output=$output_type);

        // Base implementation with wrapped type on the LHS and wrapper on the RHS
        impl<'a, N: MpcNetwork + Send, S: SharedValueSource> $trait<&'a $wrapper_type> for &'a $wrapped_type {
            // Output is always the wrapper type
            type Output = $output_type;

            fn $fn_name(self, rhs: &'a $wrapper_type) -> Self::Output {
                $from_fn(self.clone(), rhs.key_share(), rhs.network(), rhs.beaver_source()) $op rhs
            }
        }

        // Implement variants for borrowed and non-borrowed arguments
        macros::impl_operator_variants!($wrapped_type, $trait, $fn_name, $op, $wrapper_type, Output=$output_type);
    };
}

// Exports
pub(crate) use impl_arithmetic_assign;
pub(crate) use impl_authenticated;
pub(crate) use impl_delegated;
pub(crate) use impl_delegated_wrapper;
pub(crate) use impl_operator_variants;
pub(crate) use impl_wrapper_type;
