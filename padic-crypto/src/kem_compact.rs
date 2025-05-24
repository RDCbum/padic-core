#![deny(warnings)]
#![allow(clippy::redundant_clone)]

use crate::fo;
use blake3;
use padic_core::Mod5;
use rand::{rng, Rng};
use crate::error::DeserializeError;

/* ---------- parámetros públicos ---------- */
pub const N: usize = 109;
pub const R_PARAM: u32 = 12;
pub const Q: u128 = 5u128.pow(R_PARAM);

pub const BYTES_PER_COEFF: usize = 16; // u128 little-endian
pub const PK_LEN: usize = (N * N + N) * BYTES_PER_COEFF;
pub const SK_LEN: usize = N * BYTES_PER_COEFF;
pub const CT_LEN: usize = (N + 1) * BYTES_PER_COEFF;

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

/* ---------- serialización binaria ---------- */
impl PublicKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PK_LEN);
        for row in &self.a {
            for c in row {
                out.extend_from_slice(&c.value().to_le_bytes());
            }
        }
        for c in &self.t {
            out.extend_from_slice(&c.value().to_le_bytes());
        }
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, DeserializeError> {
        if buf.len() != PK_LEN {
            return Err(DeserializeError::Length);
        }
        let mut off = 0;
        let mut a = Vec::with_capacity(N);
        for _ in 0..N {
            let mut row = Vec::with_capacity(N);
            for _ in 0..N {
                let mut tmp = [0u8; 16];
                tmp.copy_from_slice(&buf[off..off + 16]);
                off += 16;
                row.push(Mod5::new(u128::from_le_bytes(tmp) as i128, R_PARAM));
            }
            a.push(row);
        }
        let mut t = Vec::with_capacity(N);
        for _ in 0..N {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            t.push(Mod5::new(u128::from_le_bytes(tmp) as i128, R_PARAM));
        }
        Ok(Self { a, t })
    }
}

impl SecretKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SK_LEN);
        for c in &self.s {
            out.extend_from_slice(&c.value().to_le_bytes());
        }
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, DeserializeError> {
        if buf.len() != SK_LEN {
            return Err(DeserializeError::Length);
        }
        let mut s = Vec::with_capacity(N);
        for chunk in buf.chunks_exact(16) {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(chunk);
            s.push(Mod5::new(u128::from_le_bytes(tmp) as i128, R_PARAM));
        }
        Ok(Self { s })
    }
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CT_LEN);
        for c in &self.u {
            out.extend_from_slice(&c.value().to_le_bytes());
        }
        out.extend_from_slice(&self.v.value().to_le_bytes());
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, DeserializeError> {
        if buf.len() != CT_LEN {
            return Err(DeserializeError::Length);
        }
        let mut off = 0;
        let mut u = Vec::with_capacity(N);
        for _ in 0..N {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(&buf[off..off + 16]);
            off += 16;
            u.push(Mod5::new(u128::from_le_bytes(tmp) as i128, R_PARAM));
        }
        let mut tmp = [0u8; 16];
        tmp.copy_from_slice(&buf[off..off + 16]);
        let v = Mod5::new(u128::from_le_bytes(tmp) as i128, R_PARAM);
        Ok(Self { u, v })
    }
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
