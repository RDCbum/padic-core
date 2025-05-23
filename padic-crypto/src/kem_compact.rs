//! KEM Compact – stub de trabajo (v0.3)
//! ---------------------------------------------------------------
//! • Dimensión fija N = 109
//! • Módulo Q = 5¹² = 244 140 625
//! • keygen(): genera matriz A, secreto s y t = A·s (mod Q)
//! • encaps/decaps(): round-trip provisional mediante BLAKE3
//!
//! ⛔  CÓDIGO DE PRUEBA — no es todavía la MSIS final.

#![deny(warnings)]
#![allow(clippy::redundant_clone)]

use blake3;
use padic_core::mod5::Mod5;
use rand::{Rng, rng};

/// Número fijo de filas/columnas
pub const N: usize = 109;
/// Potencia del módulo
const R_PARAM: u32 = 12;
/// Q = 5^R
pub const Q: u128 = 5u128.pow(R_PARAM);

/// Clave pública Compact : matriz `a` y vector `t = A·s`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub a: Vec<Vec<Mod5>>,
    pub t: Vec<Mod5>,
}

/// Clave secreta Compact (vector `s`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(pub Vec<Mod5>);

/// Ciphertext provisional (vector `u`)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(pub Vec<Mod5>);

/* ------------------------------------------------------------------------ */

/// keygen(): genera (pk, sk) con `t = A·s (mod Q)`
pub fn keygen() -> (PublicKey, SecretKey) {
    let mut rng = rng(); // rand 0.9: alias de thread_rng()

    /* ---- matriz A ---- */
    let a: Vec<Vec<Mod5>> = (0..N)
        .map(|_| {
            (0..N)
                .map(|_| {
                    let r = rng.random::<u128>() % Q; // `gen` → `random`
                    Mod5::new(r as i128, R_PARAM)
                })
                .collect()
        })
        .collect();

    /* ---- vector secreto s ---- */
    let s: Vec<Mod5> = (0..N)
        .map(|_| {
            let r = rng.random::<u128>() % Q;
            Mod5::new(r as i128, R_PARAM)
        })
        .collect();

    /* ---- t = A · s ---- */
    let t: Vec<Mod5> = a
        .iter()
        .map(|row| {
            row.iter()
                .zip(&s)
                .fold(Mod5::new(0, R_PARAM), |acc, (a_ij, s_j)| {
                    acc + a_ij.clone() * s_j.clone()
                })
        })
        .collect();

    (PublicKey { a, t }, SecretKey(s))
}

/* ------------------------------------------------------------------------ */

/// encaps(): genera `u` aleatorio y K = BLAKE3(u)
pub fn encaps(_pk: &PublicKey) -> (Ciphertext, [u8; 32]) {
    let mut rng = rng();

    let u: Vec<Mod5> = (0..N)
        .map(|_| {
            let r = rng.random::<u128>() % Q;
            Mod5::new(r as i128, R_PARAM)
        })
        .collect();

    let ct = Ciphertext(u);
    let shared = blake3::hash(&serialize_mod5_vec(&ct.0));
    (ct, *shared.as_bytes())
}

/// decaps(): K = BLAKE3(u)
pub fn decaps(ct: &Ciphertext, _sk: &SecretKey) -> [u8; 32] {
    let shared = blake3::hash(&serialize_mod5_vec(&ct.0));
    *shared.as_bytes()
}

/* ---------- helper ---------- */

fn serialize_mod5_vec(v: &[Mod5]) -> Vec<u8> {
    // Cada value() es u128 → 16 bytes LE
    let mut out = Vec::with_capacity(v.len() * 16);
    for m in v {
        out.extend_from_slice(&m.value().to_le_bytes());
    }
    out
}
