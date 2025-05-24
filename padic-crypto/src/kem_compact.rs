#![deny(warnings)]
#![allow(clippy::redundant_clone)]

use crate::fo;
use blake3;
use padic_core::Mod5;
use rand::{rng, Rng};

/* ---------- parámetros públicos ---------- */
pub const N: usize = 109;
pub const R_PARAM: u32 = 12;
pub const Q: u128 = 5u128.pow(R_PARAM);

/* ---------- structs ---------- */

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

/* ---------- keygen ---------- */

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

/* ---------- encaps ---------- */

pub fn encaps(pk: &PublicKey) -> (Ciphertext, [u8; 32]) {
    use crate::enc_core;

    let mut rng = rng();
    let (u, v, r, _) = enc_core::enc_core(pk, &mut rng);

    // re-derivación de r' hasta coincidir (máx 4 intentos)
    for _ in 0..4 {
        if fo::derive_r(pk, &u, &v) == r {
            break;
        }
    }

    let mut buf = serialize_mod5_vec(&u);
    buf.extend_from_slice(&v.value().to_le_bytes());
    let k_good = blake3::hash(&buf);

    (Ciphertext { u, v }, *k_good.as_bytes())
}

/* ---------- decaps ---------- */

pub fn decaps(ct: &Ciphertext, _sk: &SecretKey, pk: &PublicKey) -> [u8; 32] {
    let r_prime = fo::derive_r(pk, &ct.u, &ct.v);
    let u_prime: Vec<Mod5> = pk.a.iter().map(|row| dot(row, &r_prime)).collect();
    let v_prime = dot(&pk.t, &r_prime);

    // diff = 0 si u',v' coinciden con ct
    let mut diff = ct.v.value() ^ v_prime.value();
    for (a, b) in ct.u.iter().zip(&u_prime) {
        diff |= a.value() ^ b.value();
    }
    diff |= diff >> 64;
    diff |= diff >> 32;
    diff |= diff >> 16;
    diff |= diff >> 8;
    let mask = ((!diff as u8) & 1).wrapping_sub(1); // 0xFF good, 0x00 bad

    let mut buf = serialize_mod5_vec(&ct.u);
    buf.extend_from_slice(&ct.v.value().to_le_bytes());
    let k_good = blake3::hash(&buf);
    let k_bad = blake3::hash(b"fail");

    select_ct(mask, *k_good.as_bytes(), *k_bad.as_bytes())
}

/* ---------- helpers ---------- */

pub fn serialize_mod5_vec(v: &[Mod5]) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * 16);
    for m in v {
        out.extend_from_slice(&m.value().to_le_bytes());
    }
    out
}

pub fn dot(a: &[Mod5], b: &[Mod5]) -> Mod5 {
    a.iter().zip(b).fold(Mod5::new(0, R_PARAM), |acc, (x, y)| {
        acc + x.clone() * y.clone()
    })
}

/// Selección CT (mask: 0xFF elige good, 0x00 elige bad)
fn select_ct(mask: u8, k_good: [u8; 32], k_bad: [u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = (k_good[i] & mask) | (k_bad[i] & !mask);
    }
    out
}
