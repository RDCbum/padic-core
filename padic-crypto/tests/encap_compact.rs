use padic_core::mod5::Mod5;
use padic_crypto::kem_compact::{decaps, encaps, keygen};

#[test]
fn encap_roundtrip() {
    let (pk, sk) = keygen();

    /* flujo normal */
    let (mut ct, k_enc) = encaps(&pk);
    let k_dec = decaps(&ct, &sk, &pk);
    assert_eq!(k_enc, k_dec);

    /* corrupción de un coeficiente de u */
    ct.u[0] = ct.u[0].clone() + Mod5::new(1, 12); //  ←  clone() para no mover
    let k_bad = decaps(&ct, &sk, &pk);
    assert_ne!(k_enc, k_bad);
}
