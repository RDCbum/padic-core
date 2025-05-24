#![deny(warnings)]

use padic_core::mod5::Mod5;
use padic_crypto::{
    agg_sig::aggregate,
    sign_compact::{
        hash_challenge, keygen, mat_vec_mul_mod, sign, verify, PublicKey, Signature, R,
    },
};

/// u = A·z + m·t  (m = −1 si c impar, 0 si par)
fn derive_u(pk: &PublicKey, sig: &Signature, msg: &[u8]) -> Vec<Mod5> {
    let m = if sig.c & 1 == 1 { -1 } else { 0 };
    let mut u = mat_vec_mul_mod(&pk.a, &sig.z);
    for (ui, ti) in u.iter_mut().zip(&pk.t) {
        *ui = ui.clone() + ti.clone() * Mod5::new(m, R);
    }
    assert_eq!(hash_challenge(pk, &u, msg), sig.c);
    u
}

#[test]
fn aggregate_two_signatures_scaffold() {
    let msg = b"hello padlock p-tsig";

    // Firmante 1
    let kp1 = keygen();
    let sig1 = sign(&kp1, msg);
    assert!(verify(&kp1.pk, msg, &sig1));
    let u1 = derive_u(&kp1.pk, &sig1, msg);

    // Firmante 2: repetir hasta que c coincida con sig1.c
    let (_kp2, sig2, u2) = loop {
        let kp = keygen();
        let sig = sign(&kp, msg);
        if sig.c == sig1.c {
            assert!(verify(&kp.pk, msg, &sig));
            let u = derive_u(&kp.pk, &sig, msg);
            break (kp, sig, u);
        }
    };

    // Agregamos (la verificación π SIS llegará en Sprint D-3)
    let _agg = aggregate(&[sig1, sig2], &[u1, u2]);

    // Placeholder mientras no exista proof::verify
    assert!(true);
}

#[test]
#[should_panic(expected = "p-TSig necesita")]
fn aggregate_empty_panics() {
    let _ = aggregate(&[], &[]);
}
