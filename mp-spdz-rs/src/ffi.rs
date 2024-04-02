//! The FFI bindings for the MP-SPDZ library

#[cxx::bridge]
mod ffi_inner {
    unsafe extern "C++" {
        include!("FHE/FHE_Params.h");
        include!("FHE/FHE_Keys.h");
        include!("FHE/Plaintext.h");
        include!("Math/bigint.h");

        // `bigint`
        type bigint;
        fn print(self: &bigint);

        // `FHE_Params`
        type FHE_Params;
        fn new_fhe_params(n_mults: i32, drown_sec: i32) -> UniquePtr<FHE_Params>;
        fn basic_generation_mod_prime(self: Pin<&mut FHE_Params>, plaintext_length: i32);
        fn get_plaintext_mod(params: &FHE_Params) -> UniquePtr<bigint>;

        // `FHE Keys`
        type FHE_KeyPair;
        type FHE_PK;
        type FHE_SK;
        fn new_keypair(params: &FHE_Params) -> UniquePtr<FHE_KeyPair>;
        fn get_pk(keypair: &FHE_KeyPair) -> UniquePtr<FHE_PK>;
        fn get_sk(keypair: &FHE_KeyPair) -> UniquePtr<FHE_SK>;
        fn encrypt(keypair: &FHE_KeyPair, plaintext: &Plaintext_mod_prime)
            -> UniquePtr<Ciphertext>;
        fn decrypt(
            keypair: Pin<&mut FHE_KeyPair>,
            ciphertext: &Ciphertext,
        ) -> UniquePtr<Plaintext_mod_prime>;

        // `Plaintext`
        type Plaintext_mod_prime;
        fn new_plaintext(params: &FHE_Params) -> UniquePtr<Plaintext_mod_prime>;
        fn set_element_int(plaintext: Pin<&mut Plaintext_mod_prime>, idx: usize, value: u32);
        fn get_element_int(plaintext: &Plaintext_mod_prime, idx: usize) -> u32;

        // `Ciphertext`
        type Ciphertext;
        fn add_ciphertexts(c0: &Ciphertext, c1: &Ciphertext) -> UniquePtr<Ciphertext>;
        fn mul_ciphertexts(c0: &Ciphertext, c1: &Ciphertext, pk: &FHE_PK) -> UniquePtr<Ciphertext>;
    }
}
pub use ffi_inner::*;

#[cfg(test)]
mod test {
    use cxx::UniquePtr;
    use rand::{thread_rng, Rng, RngCore};

    use super::*;

    /// Generate a new set of FHE parameters and keypair
    fn setup_fhe(
        n_mults: i32,
        plaintext_length: i32,
    ) -> (UniquePtr<FHE_Params>, UniquePtr<FHE_KeyPair>) {
        let mut params = new_fhe_params(n_mults, 128 /* sec */);
        params.pin_mut().basic_generation_mod_prime(plaintext_length);

        let keypair = new_keypair(&params);
        (params, keypair)
    }

    /// Create a ciphertext encrypting a single integer in the zero'th slot
    fn encrypt_int(
        params: &FHE_Params,
        keypair: &FHE_KeyPair,
        value: u32,
    ) -> UniquePtr<Ciphertext> {
        let mut plaintext = new_plaintext(params);
        set_element_int(plaintext.pin_mut(), 0 /* idx */, value);

        encrypt(keypair, &plaintext)
    }

    /// Tests addition of two encrypted values
    #[test]
    fn test_encrypted_addition() {
        let mut rng = thread_rng();
        let (params, mut keypair) = setup_fhe(0, 254);

        // Add two ciphertexts, divide by two to avoid overflow
        let val1 = rng.next_u32() / 2;
        let val2 = rng.next_u32() / 2;

        let cipher1 = encrypt_int(&params, &keypair, val1);
        let cipher2 = encrypt_int(&params, &keypair, val2);

        let sum = add_ciphertexts(cipher1.as_ref().unwrap(), cipher2.as_ref().unwrap());

        // Decrypt the sum
        let plaintext_res = decrypt(keypair.pin_mut(), &sum);
        let pt_u32 = get_element_int(&plaintext_res, 0);
        let expected = val1 + val2;

        assert_eq!(pt_u32, expected);
    }

    /// Tests multiplication of two encrypted values
    #[test]
    fn test_encrypted_multiplication() {
        let mut rng = thread_rng();
        let (params, mut keypair) = setup_fhe(1, 254);

        // Multiply two ciphertexts; capped bit length to avoid overflow
        let range = (0..(2u32.pow(16)));
        let val1 = rng.gen_range(range.clone());
        let val2 = rng.gen_range(range.clone());

        let cipher1 = encrypt_int(&params, &keypair, val1);
        let cipher2 = encrypt_int(&params, &keypair, val2);

        let pk = get_pk(&keypair);
        let product = mul_ciphertexts(
            cipher1.as_ref().unwrap(),
            cipher2.as_ref().unwrap(),
            pk.as_ref().unwrap(),
        );

        // Decrypt the product
        let plaintext_res = decrypt(keypair.pin_mut(), &product);
        let pt_u32 = get_element_int(&plaintext_res, 0);
        let expected = val1 * val2;

        assert_eq!(pt_u32, expected);
    }
}
