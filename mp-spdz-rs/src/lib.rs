//! Defines rust FFI bindings for the LowGear implementation in MP-SPDZ
//! written in c++
//!
//! This library is intended to be a thin wrapper around the MP-SPDZ library,
//! and to internalize build and link procedure with the foreign ABI

#[cxx::bridge]
pub mod ffi {
    struct Test {
        a: i32,
        b: i32,
    }

    unsafe extern "C++" {
        include!("FHE/Ring_Element.h");

        fn test_method();
    }
}

#[cfg(test)]
mod test {
    use crate::ffi::test_method;

    #[test]
    fn test_dummy() {
        test_method();
    }
}
