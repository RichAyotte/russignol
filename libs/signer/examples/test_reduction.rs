//! Test modular reduction

use std::mem::MaybeUninit;

fn main() {
    let key_bytes =
        hex::decode("b55a861f1948dd6810d4e3acf65c6d323925049f7ea98f10d9809154cb03ec46").unwrap();

    println!("Original bytes: {}", hex::encode(&key_bytes));

    let mut scalar = MaybeUninit::<blst::blst_scalar>::uninit();

    unsafe {
        blst::blst_scalar_from_bendian(scalar.as_mut_ptr(), key_bytes.as_ptr());
        let scalar = scalar.assume_init();

        // Convert scalar back to bytes
        let mut reduced_bytes = [0u8; 32];
        blst::blst_bendian_from_scalar(reduced_bytes.as_mut_ptr(), &raw const scalar);

        println!("Reduced bytes:  {}", hex::encode(reduced_bytes));

        // Check if reduced
        println!("\nFirst byte comparison:");
        println!("  Original:    0x{:02x}", key_bytes[0]);
        println!("  Reduced:     0x{:02x}", reduced_bytes[0]);
        println!("  Curve order: 0x73");

        // Try to create secret key
        match blst::min_pk::SecretKey::from_bytes(&reduced_bytes) {
            Ok(_) => println!("\n✓ Successfully created secret key from reduced bytes"),
            Err(e) => println!("\n✗ Failed to create secret key: {e:?}"),
        }
    }
}
