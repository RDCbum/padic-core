use padic_crypto::kem_compact::{self, N, Q};

#[test]
fn keygen_dimensions() {
    let (pk, sk) = kem_compact::keygen();
    assert_eq!(pk.a.len(), N);
    for row in &pk.a {
        assert_eq!(row.len(), N);
    }
    assert_eq!(pk.t.len(), N);
    assert_eq!(sk.0.len(), N);
}

#[test]
fn keygen_coeffs_below_q() {
    let (pk, sk) = kem_compact::keygen();
    for row in &pk.a {
        for m in row {
            assert!(m.value() < Q);
        }
    }
    for m in &pk.t {
        assert!(m.value() < Q);
    }
    for m in &sk.0 {
        assert!(m.value() < Q);
    }
}
