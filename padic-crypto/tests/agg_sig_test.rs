//! Tests de la firma agregada p-TSig

use padic_core::mod5::Mod5;
use padic_crypto::{
    agg_sig::{aggregate, verify_agg},
    sign_compact::{keygen, mat_vec_mul_mod, Keypair, PublicKey, Signature, R},
};

/// Compromiso u = A·z + m·t  (misma fórmula que `verify_agg`)
fn commitment_u(pk: &PublicKey, sig: &Signature) -> Vec<Mod5> {
    let m: i128 = if sig.c & 1 == 1 { -1 } else { 0 };
    let mut u = mat_vec_mul_mod(&pk.a, &sig.z);
    for (ui, ti) in u.iter_mut().zip(&pk.t) {
        *ui = ui.clone() + ti.clone() * Mod5::new(m, R);
    }
    u
}

#[test]
fn aggregate_stores_full_z_list_and_verifies() {
    const K: usize = 3;
    const MSG: &[u8] = b"hola padlock";

    // 1. Un solo firmante genera pk, sig, u
    let kp: Keypair = keygen();
    let sig: Signature = padic_crypto::sign_compact::sign(&kp, MSG);
    let u = commitment_u(&kp.pk, &sig);

    // 2. Reutilizamos la MISMA firma k veces para forzar c idéntico
    let pks = vec![kp.pk.clone(); K];
    let sigs = vec![sig.clone(); K];
    let us = vec![u.clone(); K];

    // 3. Aggregate y verifica
    let agg = aggregate(&sigs, &us);

    // z_list contiene exactamente las k copias
    assert_eq!(agg.z_list.len(), K);
    for stored in &agg.z_list {
        assert_eq!(&sig.z, stored);
    }

    assert!(verify_agg(&pks, &agg, MSG));
}

#[test]
fn verify_fails_if_weight_exceeds_bound() {
    const K: usize = 2;
    let kp: Keypair = keygen();
    let mut sig: Signature = padic_crypto::sign_compact::sign(&kp, b"x");

    // Crear z con peso máximo para disparar la condición
    sig.z = vec![Mod5::new(1, R); R as usize];
    let u = commitment_u(&kp.pk, &sig);

    let pks = vec![kp.pk.clone(); K];
    let sigs = vec![sig.clone(), sig];
    let us = vec![u.clone(), u];

    let agg = aggregate(&sigs, &us);

    assert!(!verify_agg(&pks, &agg, b"x"));
}
