use padic_core::mod5::Mod5; // ← import
use padic_crypto::sign_compact::*;

#[test]
fn roundtrip_signature() {
    let kp = keygen();
    let msg = b"MSIS compact test";

    let sig = sign(&kp, msg);
    assert!(verify(&kp.pk, msg, &sig));

    // Firma corrupta
    let mut bad_sig = sig.clone();
    bad_sig.z[0] = bad_sig.z[0].clone() + Mod5::new(1, R);
    assert!(!verify(&kp.pk, msg, &bad_sig));
}
