#![deny(warnings)]

use padic_core::mod5::Mod5;
use padic_crypto::agg_sig::aggregate;
use padic_crypto::sign_compact::{keygen, sign, verify, M, R};

#[test]
fn aggregate_two_identical_signatures() {
    let msg = b"padlock-ptest";
    let kp = keygen();

    // Firma individual
    let sig = sign(&kp, msg);
    assert!(verify(&kp.pk, msg, &sig));

    // ── lista de firmas y lista de u (dummy) ───────────────────────
    let sigs = [sig.clone(), sig.clone()];
    let u_dummy = vec![vec![Mod5::new(0, R); M]; sigs.len()];

    let agg = aggregate(&sigs, &u_dummy);

    assert_eq!(agg.z_sum.len(), sig.z.len());
    assert_eq!(agg.c, sig.c);
}

#[test]
#[should_panic(expected = "p-TSig needs 1‒16")]
fn aggregate_empty_panics() {
    let sigs: [padic_crypto::sign_compact::Signature; 0] = [];
    let u_list: [Vec<Mod5>; 0] = [];
    let _ = aggregate(&sigs, &u_list);
}
