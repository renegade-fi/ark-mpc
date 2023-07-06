//! Defines macros useful for creating arithmetic implementations

/// Given an implementation of an arithmetic trait on two borrowed references, this macro
/// implements the same arithmetic on the owned and partially-owned variants
macro_rules! impl_borrow_variants {
    // Single type trait
    ($target:ty, $trait:ident, $fn_name:ident, $op:tt) => {
        // Single implementation, owned target type
        impl $trait for $target {
            type Output = $target;

            fn $fn_name(self) -> Self::Output {
                $op &self
            }
        }
    };

    // Output type same as left hand side
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty) => {
        impl_borrow_variants!($lhs, $trait, $fn_name, $op, $rhs, Output=$lhs);
    };

    // Output type specified
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty, Output=$out_type:ty) => {
        /// lhs borrowed, rhs owned
        impl<'a> $trait<$rhs> for &'a $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                self $op &rhs
            }
        }

        /// lhs owned, rhs borrowed
        impl<'a> $trait<&'a $rhs> for $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: &'a $rhs) -> Self::Output {
                &self $op rhs
            }
        }

        /// lhs owned, rhs owned
        impl $trait<$rhs> for $lhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: $rhs) -> Self::Output {
                &self $op &rhs
            }
        }
    }
}

/// A macro to implement commutative variants of a binary operation
macro_rules! impl_commutative {
    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty) => {
        impl_commutative!($lhs, $trait, $fn_name, $op, $rhs, Output=$lhs);
    };

    ($lhs:ty, $trait:ident, $fn_name:ident, $op:tt, $rhs:ty, Output=$out_type:ty) => {
        /// lhs borrowed, rhs borrowed
        impl<'a> $trait<&'a $lhs> for &'a $rhs {
            type Output = $out_type;

            fn $fn_name(self, rhs: &'a $lhs) -> Self::Output {
                rhs $op self
            }
        }

        /// lhs borrowed, rhs owned
        impl<'a> $trait<$lhs> for &'a $rhs
        {
            type Output = $out_type;

            fn $fn_name(self, rhs: $lhs) -> Self::Output {
                &rhs $op self
            }
        }

        /// lhs owned, rhs borrowed
        impl<'a> $trait<&'a $lhs> for $rhs
        {
            type Output = $out_type;

            fn $fn_name(self, rhs: &'a $lhs) -> Self::Output {
                rhs $op &self
            }
        }

        /// lhs owned, rhs owned
        impl $trait<$lhs> for $rhs
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
