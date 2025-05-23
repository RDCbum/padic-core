use padic_crypto::kem_compact::{keygen, N, Q};

#[test]
fn keygen_dimensions() {
    let (pk, sk) = keygen();
    assert_eq!(pk.a.len(), N);
    assert_eq!(pk.t.len(), N);
    assert_eq!(sk.s.len(), N);
}

#[test]
fn keygen_coeffs_below_q() {
    let (pk, sk) = keygen();

    // Cada coeficiente de A, t y s está dentro de [0, Q)
    for row in &pk.a {
        for a_ij in row {
            assert!(a_ij.value() < Q);
        }
    }
    for t_i in &pk.t {
        assert!(t_i.value() < Q);
    }

    for s_i in &sk.s {
        assert!(s_i.value() < Q);
    }

    // ── NUEVA COMPROBACIÓN:  t = A·s  ───────────────────────────
    // volvemos a calcular t' = A·s  y comparamos con pk.t
    for (i, row) in pk.a.iter().enumerate() {
        let mut acc = padic_core::mod5::Mod5::new(0, 12);
        for (a_ij, s_j) in row.iter().zip(&sk.s) {
            acc = acc + a_ij.clone() * s_j.clone();
        }
        assert_eq!(acc, pk.t[i], "fila {i} de t no coincide");
    }
}
