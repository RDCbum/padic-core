use padic_crypto::kem_compact::{keygen, N, Q};

#[test]
fn keygen_compact_sizes() {
    let (pk, sk) = keygen();

    /* tamaños correctos */
    assert_eq!(pk.a.len(), N);
    assert_eq!(pk.t.len(), N);
    assert_eq!(sk.s.len(), N); //  ←  sk.s  (campo con nombre)

    /* coeficientes < Q */
    for row in &pk.a {
        for a_ij in row {
            assert!(a_ij.value() < Q);
        }
    }
    for s_i in &sk.s {
        assert!(s_i.value() < Q);
    }

    /* verificar t = A·s (mod Q) */
    for (row, t_i) in pk.a.iter().zip(&pk.t) {
        let prod = row.iter().zip(&sk.s).fold(0u128, |acc, (a_ij, s_j)| {
            acc + (a_ij.clone() * s_j.clone()).value()
        });
        assert_eq!(t_i.value(), prod % Q);
    }
}
