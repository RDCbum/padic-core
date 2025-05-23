use padic_crypto::{
    enc_core,
    kem_compact::{self, N, Q},
};
use rand::rng;

#[test]
fn enc_core_outputs_in_range() {
    let (pk, _sk) = kem_compact::keygen();
    let mut rng = rng();
    let (u, v, _r, _e) = enc_core::enc_core(&pk, &mut rng);
    assert_eq!(u.len(), N);
    for coeff in &u {
        assert!(coeff.value() < Q);
    }
    assert!(v.value() < Q);
}
