//! Defines rust FFI bindings for the LowGear implementation in MP-SPDZ
//! written in c++
//!
//! This library is intended to be a thin wrapper around the MP-SPDZ library,
//! and to internalize build and link procedure with the foreign ABI

#[cxx::bridge]
pub mod ffi {
    unsafe extern "C++" {
        include!("FHE/FHE_Params.h");
        include!("Math/bigint.h");

        // `bigint`
        type bigint;
        fn print(self: &bigint);

        // `FHE_Params`
        type FHE_Params;
        fn new_fhe_params(n_mults: i32, drown_sec: i32) -> UniquePtr<FHE_Params>;
        fn basic_generation_mod_prime(self: Pin<&mut FHE_Params>, plaintext_length: i32);
        fn get_plaintext_mod(params: &FHE_Params) -> UniquePtr<bigint>;
    }
}

#[cfg(test)]
mod test {
    use super::ffi::*;

    #[test]
    fn test_dummy() {
        let mut params = new_fhe_params(0 /* mults */, 128 /* sec */);
        params.pin_mut().basic_generation_mod_prime(255 /* bitlength */);

        let plaintext_modulus = get_plaintext_mod(&params);
        plaintext_modulus.print();
    }
}
