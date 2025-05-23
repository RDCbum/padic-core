use padic_crypto::kem_compact::{decaps, encaps, keygen};

#[test]
fn fo_roundtrip_ok() {
    let (pk, sk) = keygen();
    let (ct, k1) = encaps(&pk);
    let k2 = decaps(&ct, &sk, &pk);
    assert_eq!(k1, k2);
}

#[test]
fn fo_roundtrip_corrupted() {
    use padic_core::Mod5;
    let (pk, sk) = keygen();
    let (mut ct, k1) = encaps(&pk);
    ct.u[0] = ct.u[0].clone() + Mod5::new(1, 12); // flip coef
    let k2 = decaps(&ct, &sk, &pk);
    assert_ne!(k1, k2);
}
