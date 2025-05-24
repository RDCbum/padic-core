// padic_crypto/tests/agg_roundtrip.rs
#![deny(warnings)]

use padic_crypto::agg_sig::aggregate; // ← solo aggregate
use padic_crypto::sign_compact::{keygen, sign, verify};

#[test]
fn aggregate_two_identical_signatures() {
    let msg = b"padlock-ptest";
    let kp = keygen();

    let sig = sign(&kp, msg);
    assert!(verify(&kp.pk, msg, &sig));

    let agg = aggregate(&[sig.clone(), sig.clone()]);

    assert_eq!(agg.z_sum.len(), sig.z.len());
    assert_eq!(agg.c, sig.c);
}

#[test]
#[should_panic(expected = "supports 1..=16")]
fn aggregate_empty_panics() {
    let _ = aggregate(&[]);
}
