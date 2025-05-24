//! Firma agregada p-TSig (Tier-A Compact) – Sprint D-2
//!
//! · 1 ≤ k ≤ 16 firmantes sobre el mismo mensaje y desafío único c.
//! · Cada firmante publica su compromiso uᵢ (= A·yᵢ).
//! · aggregate(): guarda z_list, calcula z_sum y comprueba que todos comparten c.
//! · verify_agg(): valida hash, ecuaciones y peso.
//!
//! Constantes heredadas de sign_compact:
//!     R = 12   (bit-depth)
//!     M = 93   (#filas A)
//!     OMEGA = 47 (límite de peso)
//!
//! Nota 🔒 Esta verificación aún no es totalmente CT: las ramas dependen de
//! entrada pública. Cuando pasemos a la prueba π SIS batch añadiremos masking.

#![deny(warnings)]

use crate::sign_compact::{hash_challenge, mat_vec_mul_mod, PublicKey, Signature, OMEGA, R};
use padic_core::mod5::Mod5;

/* ---------- Tipo principal ---------- */

/// Firma agregada: lista completa z_list, suma z_sum, reto c y compromisos uᵢ.
#[derive(Clone, Debug)]
pub struct AggregateSig {
    pub z_sum: Vec<Mod5>,       // Σ zᵢ  (longitud N)
    pub z_list: Vec<Vec<Mod5>>, // k × N
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
    let z_len = sigs[0].z.len(); // N = 109
    let u_len = u_list[0].len(); // M = 93

    let mut z_sum = vec![Mod5::new(0, R); z_len];
    let mut z_list = Vec::with_capacity(sigs.len());

    for (sig, u) in sigs.iter().zip(u_list) {
        assert_eq!(sig.c, c0, "los desafíos c no coinciden");
        assert_eq!(sig.z.len(), z_len, "longitud z desigual");
        assert_eq!(u.len(), u_len, "longitud u desigual");

        // acumular Σ zᵢ
        for (acc, zi) in z_sum.iter_mut().zip(&sig.z) {
            *acc = acc.clone() + zi.clone();
        }
        z_list.push(sig.z.clone());
    }

    AggregateSig {
        z_sum,
        z_list,
        c: c0,
        u_list: u_list.to_vec(),
    }
}

/* ---------- Verificación agregada ---------- */

pub fn verify_agg(pks: &[PublicKey], agg: &AggregateSig, msg: &[u8]) -> bool {
    let k = pks.len();
    if k == 0 || k > 16 || k != agg.u_list.len() || k != agg.z_list.len() {
        return false;
    }

    let m_scalar = ct_mask(agg.c & 1);
    let m_mod5 = Mod5::new(m_scalar, R);

    // 1-3) hash, tamaños, ecuación A·zᵢ = uᵢ + m·t
    for ((pk, u), z) in pks.iter().zip(&agg.u_list).zip(&agg.z_list) {
        // 1) hash
        if hash_challenge(pk, u, msg) != agg.c {
            return false;
        }

        // 2) coherencia de tamaños
        if u.len() != pk.t.len() || z.len() != pk.a[0].len() {
            return false;
        }

        // 3) ecuación por firmante
        let mut lhs = mat_vec_mul_mod(&pk.a, z);
        for (lhs_j, t_j) in lhs.iter_mut().zip(&pk.t) {
            *lhs_j = lhs_j.clone() + t_j.clone() * m_mod5.clone();
        }
        if &lhs != u {
            return false;
        }
    }

    // 4) peso Hamming ≤ k·Ω   (sobre w = z₁‖…‖z_k)
    let weight = agg
        .z_list
        .iter()
        .flatten()
        .filter(|c| c.value() != 0)
        .count();
    weight <= k * OMEGA
}
