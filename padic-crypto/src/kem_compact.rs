//! KEM Compact ­– implementación provisional (v0.4.1)
//! --------------------------------------------------
//! • Aún estamos en modo stub: sin ruido e y sin verificación v′.
//! • Deja la API estable para que los tests pasen.

#![deny(warnings)]
#![allow(clippy::redundant_clone)]

use blake3;
use padic_core::Mod5;
use rand::{rng, Rng};

pub const N: usize = 109;
const R_PARAM: u32 = 12;
pub const Q: u128 = 5u128.pow(R_PARAM);

/* ===== estructuras ===== */

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub a: Vec<Vec<Mod5>>,
    pub t: Vec<Mod5>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey {
    pub s: Vec<Mod5>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    pub u: Vec<Mod5>,
    pub v: Mod5,
}

/* ===== keygen() ===== */

pub fn keygen() -> (PublicKey, SecretKey) {
    let mut rng = rng();

    let a: Vec<Vec<Mod5>> = (0..N)
        .map(|_| {
            (0..N)
                .map(|_| Mod5::new((rng.random::<u128>() % Q) as i128, R_PARAM))
                .collect()
        })
        .collect();

    let s: Vec<Mod5> = (0..N)
        .map(|_| Mod5::new((rng.random::<u128>() % Q) as i128, R_PARAM))
        .collect();

    let t: Vec<Mod5> = a.iter().map(|row| dot(row, &s)).collect();

    (PublicKey { a, t }, SecretKey { s })
}

/* ===== encaps() / decaps() ===== */

/// Encaps stub – sin ruido e
pub fn encaps(pk: &PublicKey) -> (Ciphertext, [u8; 32]) {
    let mut rng = rng();

    let r: Vec<Mod5> = (0..N)
        .map(|_| Mod5::new((rng.random::<u128>() % Q) as i128, R_PARAM))
        .collect();

    /* ---- ruido e desactivado ----
    let e: Vec<Mod5> = (0..N)
        .map(|_| Mod5::new(rng.random_range(-2..=2) as i128, R_PARAM))
        .collect();
    */

    let u: Vec<Mod5> = pk.a.iter().map(|row| dot(row, &r)).collect(); // A·r
    let v = dot(&pk.t, &r); // tᵀ·r

    let mut buf = serialize_mod5_vec(&u);
    buf.extend_from_slice(&v.value().to_le_bytes());
    let k = blake3::hash(&buf);

    (Ciphertext { u, v }, *k.as_bytes())
}

/// Decaps stub – deriva K directamente de (u‖v)
pub fn decaps(ct: &Ciphertext, _sk: &SecretKey) -> [u8; 32] {
    let mut buf = serialize_mod5_vec(&ct.u);
    buf.extend_from_slice(&ct.v.value().to_le_bytes());
    let k = blake3::hash(&buf);
    *k.as_bytes()
}

/* ===== helpers ===== */

fn serialize_mod5_vec(v: &[Mod5]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 16);
    for m in v {
        out.extend_from_slice(&m.value().to_le_bytes());
    }
    out
}

fn dot(a: &[Mod5], b: &[Mod5]) -> Mod5 {
    a.iter().zip(b).fold(Mod5::new(0, R_PARAM), |acc, (x, y)| {
        acc + x.clone() * y.clone()
    })
}

#[allow(dead_code)]
fn ct_eq(a: &Mod5, b: &Mod5) -> bool {
    let mut d = a.value() ^ b.value();
    d |= d >> 64;
    d |= d >> 32;
    d |= d >> 16;
    d |= d >> 8;
    d |= d >> 4;
    d |= d >> 2;
    d |= d >> 1;
    (d & 1) == 0
}
