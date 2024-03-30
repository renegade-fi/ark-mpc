//! Defines rust FFI bindings for the LowGear implementation in MP-SPDZ
//! written in c++
//!
//! This library is intended to be a thin wrapper around the MP-SPDZ library,
//! and to internalize build and link procedure with the foreign ABI

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("FHE/Ring.h");

        type Ring;
        fn new_ring(m: i32) -> UniquePtr<Ring>;
    }
}

#[cfg(test)]
mod test {
    use super::ffi::*;

    #[test]
    fn test_dummy() {
        let ring = new_ring(10);
    }
}
