//! Firma agregada p-TSig (Tier-A Compact) – Sprint D-2
//!
//! · 1 ≤ k ≤ 16 firmantes sobre el mismo mensaje y desafío único c.
//! · Cada firmante publica su compromiso uᵢ  (= A·yᵢ).
//! · aggregate(): suma z y comprueba que c sea igual en todas las firmas.
//! · verify_agg(): valida hash, ecuaciones y peso.
//!
//! Constantes heredadas de sign_compact:
//!     R = 12,  M = 93,  OMEGA = 47
//!
//! Nota 🔒 Esta verificación aún no está 100 % CT; las ramas dependen de entrada
//! pública. Cuando pasemos a la prueba π SIS batch añadiremos masking completo.

#![deny(warnings)]

use crate::sign_compact::{hash_challenge, mat_vec_mul_mod, PublicKey, Signature, OMEGA, R};
use padic_core::mod5::Mod5;

/* ---------- Tipo principal ---------- */

/// Firma agregada con vector Σ z, reto único c y lista de compromisos uᵢ.
#[derive(Clone, Debug)]
pub struct AggregateSig {
    pub z_sum: Vec<Mod5>,
    pub c: u8,
    pub u_list: Vec<Vec<Mod5>>, // k × M
}

/* ---------- Helper ---------- */

#[inline(always)]
fn ct_mask(bit: u8) -> i128 {
    -(bit as i8 as i128) // 0 → 0  |  1 → −1
}

/* ---------- Agregación ---------- */

pub fn aggregate(sigs: &[Signature], u_list: &[Vec<Mod5>]) -> AggregateSig {
    assert!(
        (1..=16).contains(&sigs.len()) && sigs.len() == u_list.len(),
        "p-TSig necesita 1–16 firmas y lista u del mismo tamaño"
    );

    let c0 = sigs[0].c;
    let z_len = sigs[0].z.len();
    let u_len = u_list[0].len();

    let mut z_sum = vec![Mod5::new(0, R); z_len];

    for (sig, u) in sigs.iter().zip(u_list) {
        assert_eq!(sig.c, c0, "los desafíos c no coinciden");
        assert_eq!(sig.z.len(), z_len, "longitud z desigual");
        assert_eq!(u.len(), u_len, "longitud u desigual");

        for (acc, zi) in z_sum.iter_mut().zip(&sig.z) {
            *acc = acc.clone() + zi.clone();
        }
    }

    AggregateSig {
        z_sum,
        c: c0,
        u_list: u_list.to_vec(),
    }
}

/* ---------- Verificación agregada ---------- */

pub fn verify_agg(pks: &[PublicKey], agg: &AggregateSig, msg: &[u8]) -> bool {
    let k = pks.len();
    if k == 0 || k > 16 || k != agg.u_list.len() {
        return false;
    }

    // m = −1 si c impar, 0 si par
    let m_scalar = ct_mask(agg.c & 1);

    // 1-2) comprobar hash y tamaños
    for (pk, u) in pks.iter().zip(&agg.u_list) {
        if hash_challenge(pk, u, msg) != agg.c {
            return false;
        }
        if u.len() != pk.t.len() {
            return false;
        }
    }

    // 3) ecuaciones A·z_sum = u + m·t   fila a fila
    for (pk, u) in pks.iter().zip(&agg.u_list) {
        // lhs = A·z_sum
        let mut lhs = mat_vec_mul_mod(&pk.a, &agg.z_sum);

        // rhs = u + m·t
        for (lhs_j, t_j) in lhs.iter_mut().zip(&pk.t) {
            *lhs_j = lhs_j.clone() + t_j.clone() * Mod5::new(m_scalar, R);
        }

        if &lhs != u {
            return false;
        }
    }

    // 4) peso Hamming ≤ k·OMEGA
    let weight = agg.z_sum.iter().filter(|c| c.value() != 0).count();
    weight <= k * OMEGA
}
