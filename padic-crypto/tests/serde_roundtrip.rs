#![deny(warnings)]

use padic_crypto::{
    kem_compact::{keygen as kem_keygen, Ciphertext},
    sign_compact::{keygen as sig_keygen, Signature},
};

#[test]
fn kem_pk_sk_roundtrip() {
    let (pk, sk) = kem_keygen();
    let pk2 = padic_crypto::kem_compact::PublicKey::from_bytes(&pk.to_bytes()).unwrap();
    let sk2 = padic_crypto::kem_compact::SecretKey::from_bytes(&sk.to_bytes()).unwrap();
    assert_eq!(pk, pk2);
    assert_eq!(sk, sk2);
}

#[test]
fn ciphertext_roundtrip() {
    let (pk, _) = kem_keygen();
    let (ct, _) = padic_crypto::kem_compact::encaps(&pk);
    let ct2 = Ciphertext::from_bytes(&ct.to_bytes()).unwrap();
    assert_eq!(ct, ct2);
}

#[test]
fn signature_roundtrip() {
    let kp = sig_keygen();
    let msg = b"padic serde";
    let sig = padic_crypto::sign_compact::sign(&kp, msg);
    let sig2 = Signature::from_bytes(&sig.to_bytes()).unwrap();
    assert_eq!(sig, sig2);
}
