//! Defines macros useful for creating arithmetic implementations

/// Given an implementation of an arithmetic trait on two borrowed references,
/// this macro implements the same arithmetic on the owned and partially-owned
/// variants
macro_rules! impl_borrow_variants {
    // Single type trait
    ($target:ty, $trait:ident, $fn_name:ident, $op:tt, $($gen:ident: $gen_ty:ident),*) => {
        // Single implementation, owned target type
        impl<$($gen:$gen_ty),*> $trait for $target {
            type Output = $target;

            fn $fn_name(self) -> Self::Output {
                $op &self
            }
        }
    };

    // Output type same as left hand side
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty, $($gen:ident: $gen_ty:ident),*) => {
        impl_borrow_variants!($lhs, $trait, $fn_name, $op, $rhs, Output=$lhs, $($gen: $gen_ty),*);
    };

    // Output type specified
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty, Output=$out_type:ty, $($gen:ident: $gen_ty:ident),*) => {
        /// lhs borrowed, rhs owned
        impl<'a, $($gen: $gen_ty),*> $trait<$rhs> for &'a $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                self $op &rhs
            }
        }

        /// lhs owned, rhs borrowed
        impl<'a, $($gen: $gen_ty),*> $trait<&'a $rhs> for $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: &'a $rhs) -> Self::Output {
                &self $op rhs
            }
        }

        /// lhs owned, rhs owned
        impl<$($gen: $gen_ty),*> $trait<$rhs> for $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                &self $op &rhs
            }
        }
    }
}

/// A macro to implement commutative variants of a binary operation
macro_rules! impl_commutative {
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty, $($gen:ident: $gen_ty:ident),*) => {
        impl_commutative!($lhs, $trait, $fn_name, $op, $rhs, Output=$lhs, $($gen: $gen_ty),*);
    };

    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty, Output=$out_type:ty, $($gen:ident: $gen_ty:ident),*) => {
        /// lhs borrowed, rhs borrowed
        impl<'a, $($gen: $gen_ty),*> $trait<&'a $lhs> for &'a $rhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: &'a $lhs) -> Self::Output {
                rhs $op self
            }
        }

        /// lhs borrowed, rhs owned
        impl<'a, $($gen: $gen_ty),*> $trait<$lhs> for &'a $rhs
        {
            type Output = $out_type;

            fn $fn_name(self, rhs: $lhs) -> Self::Output {
                &rhs $op self
            }
        }

        /// lhs owned, rhs borrowed
        impl<'a, $($gen: $gen_ty),*> $trait<&'a $lhs> for $rhs
        {
            type Output = $out_type;

            fn $fn_name(self, rhs: &'a $lhs) -> Self::Output {
                rhs $op &self
            }
        }

        /// lhs owned, rhs owned
        impl<$($gen: $gen_ty),*> $trait<$lhs> for $rhs
        {
            type Output = $out_type;

            fn $fn_name(self, rhs: $lhs) -> Self::Output {
                &rhs $op &self
            }
        }
    };
}

pub(crate) use impl_borrow_variants;
pub(crate) use impl_commutative;
