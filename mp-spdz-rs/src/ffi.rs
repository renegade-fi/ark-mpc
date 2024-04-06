//! The FFI bindings for the MP-SPDZ library

#[allow(clippy::missing_safety_doc)]
#[allow(clippy::missing_docs_in_private_items)]
#[allow(missing_docs)]
#[allow(clippy::should_implement_trait)]
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
        fn clone(self: &bigint) -> UniquePtr<bigint>;
        unsafe fn bigint_from_be_bytes(data: *mut u8, size: usize) -> UniquePtr<bigint>;
        fn bigint_to_be_bytes(x: &bigint) -> Vec<u8>;

        // `FHE_Params`
        type FHE_Params;
        fn new_fhe_params(n_mults: i32, drown_sec: i32) -> UniquePtr<FHE_Params>;
        fn clone(self: &FHE_Params) -> UniquePtr<FHE_Params>;
        fn to_rust_bytes(self: &FHE_Params) -> Vec<u8>;
        fn fhe_params_from_rust_bytes(data: &[u8]) -> UniquePtr<FHE_Params>;

        fn n_plaintext_slots(self: &FHE_Params) -> u32;
        fn basic_generation_mod_prime(self: Pin<&mut FHE_Params>, plaintext_length: i32);
        fn param_generation_with_modulus(self: Pin<&mut FHE_Params>, plaintext_modulus: &bigint);
        fn get_plaintext_mod(params: &FHE_Params) -> UniquePtr<bigint>;

        // `FHE Keys`
        type FHE_KeyPair;
        type FHE_PK;
        type FHE_SK;
        fn new_keypair(params: &FHE_Params) -> UniquePtr<FHE_KeyPair>;

        fn clone(self: &FHE_KeyPair) -> UniquePtr<FHE_KeyPair>;
        fn clone(self: &FHE_PK) -> UniquePtr<FHE_PK>;
        fn clone(self: &FHE_SK) -> UniquePtr<FHE_SK>;

        fn to_rust_bytes(self: &FHE_PK) -> Vec<u8>;
        fn to_rust_bytes(self: &FHE_SK) -> Vec<u8>;
        fn to_rust_bytes(self: &FHE_KeyPair) -> Vec<u8>;

        fn pk_from_rust_bytes(data: &[u8], params: &FHE_Params) -> UniquePtr<FHE_PK>;
        fn sk_from_rust_bytes(data: &[u8], params: &FHE_Params) -> UniquePtr<FHE_SK>;
        fn keypair_from_rust_bytes(data: &[u8], params: &FHE_Params) -> UniquePtr<FHE_KeyPair>;

        fn get_pk(keypair: &FHE_KeyPair) -> UniquePtr<FHE_PK>;
        fn get_sk(keypair: &FHE_KeyPair) -> UniquePtr<FHE_SK>;
        fn encrypt(pk: &FHE_PK, plaintext: &Plaintext_mod_prime) -> UniquePtr<Ciphertext>;
        fn decrypt(sk: Pin<&mut FHE_SK>, ciphertext: &Ciphertext)
            -> UniquePtr<Plaintext_mod_prime>;

        // `Plaintext`
        type Plaintext_mod_prime;
        fn new_plaintext(params: &FHE_Params) -> UniquePtr<Plaintext_mod_prime>;
        fn clone(self: &Plaintext_mod_prime) -> UniquePtr<Plaintext_mod_prime>;
        fn to_rust_bytes(self: &Plaintext_mod_prime) -> Vec<u8>;
        fn plaintext_from_rust_bytes(
            data: &[u8],
            params: &FHE_Params,
        ) -> UniquePtr<Plaintext_mod_prime>;

        fn num_slots(self: &Plaintext_mod_prime) -> u32;
        fn get_element_int(plaintext: &Plaintext_mod_prime, idx: usize) -> u32;
        fn set_element_int(plaintext: Pin<&mut Plaintext_mod_prime>, idx: usize, value: u32);
        fn get_element_bigint(plaintext: &Plaintext_mod_prime, idx: usize) -> UniquePtr<bigint>;
        fn set_element_bigint(plaintext: Pin<&mut Plaintext_mod_prime>, idx: usize, value: &bigint);

        fn add_plaintexts(
            x: &Plaintext_mod_prime,
            y: &Plaintext_mod_prime,
        ) -> UniquePtr<Plaintext_mod_prime>;
        fn sub_plaintexts(
            x: &Plaintext_mod_prime,
            y: &Plaintext_mod_prime,
        ) -> UniquePtr<Plaintext_mod_prime>;
        fn mul_plaintexts(
            x: &Plaintext_mod_prime,
            y: &Plaintext_mod_prime,
        ) -> UniquePtr<Plaintext_mod_prime>;

        // `Ciphertext`
        type Ciphertext;
        fn clone(self: &Ciphertext) -> UniquePtr<Ciphertext>;
        fn to_rust_bytes(self: &Ciphertext) -> Vec<u8>;
        fn ciphertext_from_rust_bytes(data: &[u8], params: &FHE_Params) -> UniquePtr<Ciphertext>;

        fn add_plaintext(c0: &Ciphertext, p1: &Plaintext_mod_prime) -> UniquePtr<Ciphertext>;
        fn mul_plaintext(c0: &Ciphertext, p1: &Plaintext_mod_prime) -> UniquePtr<Ciphertext>;
        fn add_ciphertexts(c0: &Ciphertext, c1: &Ciphertext) -> UniquePtr<Ciphertext>;
        fn mul_ciphertexts(c0: &Ciphertext, c1: &Ciphertext, pk: &FHE_PK) -> UniquePtr<Ciphertext>;
    }
}
pub use ffi_inner::*;
unsafe impl Send for FHE_Params {}
unsafe impl Send for FHE_KeyPair {}
unsafe impl Send for FHE_PK {}
unsafe impl Send for Ciphertext {}
unsafe impl Send for Plaintext_mod_prime {}

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

    /// Create a plaintext value with the given integer in the first slot
    fn plaintext_int(val: u32, params: &FHE_Params) -> UniquePtr<Plaintext_mod_prime> {
        let mut plaintext = new_plaintext(params);
        set_element_int(plaintext.pin_mut(), 0 /* idx */, val);

        plaintext
    }

    /// Create a ciphertext encrypting a single integer in the zero'th slot
    fn encrypt_int(
        value: u32,
        keypair: &FHE_KeyPair,
        params: &FHE_Params,
    ) -> UniquePtr<Ciphertext> {
        let plaintext = plaintext_int(value, params);
        encrypt(&get_pk(keypair), &plaintext)
    }

    /// Decrypt a ciphertext and return the plaintext element in the zero'th
    /// slot
    fn decrypt_int(keypair: &FHE_KeyPair, ciphertext: &Ciphertext) -> u32 {
        let plaintext = decrypt(get_sk(keypair).pin_mut(), ciphertext);
        get_element_int(&plaintext, 0)
    }

    /// Tests converting bytes to and from a bigint
    #[test]
    fn test_bigint_to_from_bytes() {
        const N_BYTES: usize = 32;
        let mut rng = thread_rng();
        let data = rng.gen::<[u8; N_BYTES]>();

        // Convert the data to a bigint
        let bigint = unsafe { bigint_from_be_bytes(data.as_ptr() as *mut u8, N_BYTES) };
        let res = bigint_to_be_bytes(&bigint);

        assert_eq!(data.to_vec(), res);
    }

    /// Tests addition of a plaintext to a ciphertext
    #[test]
    fn test_plaintext_addition() {
        let mut rng = thread_rng();
        let (params, keypair) = setup_fhe(0, 254);

        // Add a plaintext to a ciphertext
        let val1 = rng.next_u32() / 2;
        let val2 = rng.next_u32() / 2;

        let plaintext = plaintext_int(val1, &params);
        let ciphertext = encrypt_int(val2, keypair.as_ref().unwrap(), &params);

        let sum = add_plaintext(ciphertext.as_ref().unwrap(), plaintext.as_ref().unwrap());

        // Decrypt the sum
        let plaintext_res = decrypt_int(keypair.as_ref().unwrap(), &sum);
        let expected = val1 + val2;

        assert_eq!(plaintext_res, expected);
    }

    /// Tests multiplication of a plaintext to a ciphertext
    #[test]
    fn test_plaintext_multiplication() {
        let mut rng = thread_rng();
        let (params, keypair) = setup_fhe(1, 254);

        // Multiply a plaintext to a ciphertext
        let range = 0..(2u32.pow(16));
        let val1 = rng.gen_range(range.clone());
        let val2 = rng.gen_range(range.clone());

        let plaintext = plaintext_int(val1, &params);
        let ciphertext = encrypt_int(val2, keypair.as_ref().unwrap(), &params);

        let product = mul_plaintext(ciphertext.as_ref().unwrap(), plaintext.as_ref().unwrap());

        // Decrypt the product
        let plaintext_res = decrypt_int(keypair.as_ref().unwrap(), &product);
        let expected = val1 * val2;

        assert_eq!(plaintext_res, expected);
    }

    /// Tests addition of two encrypted values
    #[test]
    fn test_encrypted_addition() {
        let mut rng = thread_rng();
        let (params, keypair) = setup_fhe(0, 254);

        // Add two ciphertexts, divide by two to avoid overflow
        let val1 = rng.next_u32() / 2;
        let val2 = rng.next_u32() / 2;

        let cipher1 = encrypt_int(val1, &keypair, &params);
        let cipher2 = encrypt_int(val2, &keypair, &params);

        let sum = add_ciphertexts(cipher1.as_ref().unwrap(), cipher2.as_ref().unwrap());

        // Decrypt the sum
        let plaintext_res = decrypt_int(keypair.as_ref().unwrap(), &sum);
        let expected = val1 + val2;

        assert_eq!(plaintext_res, expected);
    }

    /// Tests multiplication of two encrypted values
    #[test]
    fn test_encrypted_multiplication() {
        let mut rng = thread_rng();
        let (params, keypair) = setup_fhe(1, 254);

        // Multiply two ciphertexts; capped bit length to avoid overflow
        let range = 0..(2u32.pow(16));
        let val1 = rng.gen_range(range.clone());
        let val2 = rng.gen_range(range.clone());

        let cipher1 = encrypt_int(val1, &keypair, &params);
        let cipher2 = encrypt_int(val2, &keypair, &params);

        let pk = get_pk(&keypair);
        let product = mul_ciphertexts(
            cipher1.as_ref().unwrap(),
            cipher2.as_ref().unwrap(),
            pk.as_ref().unwrap(),
        );

        // Decrypt the product
        let plaintext_res = decrypt_int(keypair.as_ref().unwrap(), &product);
        let expected = val1 * val2;

        assert_eq!(plaintext_res, expected);
    }
}
