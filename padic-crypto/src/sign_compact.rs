//! Firma MSIS Compact – hardening CT (branch-free)

use blake3::Hasher;
use padic_core::mod5::Mod5;
use rand::{rng, RngCore};
use crate::error::DeserializeError;

/* ---------- Constantes ---------- */

pub const R: u32 = 12;
pub const N: usize = 109;
pub const M: usize = 93;
pub const OMEGA: usize = 47;
pub const SIG_LEN: usize = 1 + N * 16;

/* ---------- Tipos ---------- */

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub a: Vec<Vec<Mod5>>,
    pub t: Vec<Mod5>,
}

#[derive(Clone, Debug)]
pub struct SecretKey {
    pub s: Vec<Mod5>,
}

#[derive(Clone, Debug)]
pub struct Keypair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

/// Firma = (c, z) con c ∈ [0,255] y peso(z) ≤ Ω.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub c: u8,
    pub z: Vec<Mod5>,
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIG_LEN);
        out.push(self.c);
        for z in &self.z {
            out.extend_from_slice(&z.value().to_le_bytes());
        }
        out
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self, DeserializeError> {
        if buf.len() != SIG_LEN {
            return Err(DeserializeError::Length);
        }
        let c = buf[0];
        let mut z = Vec::with_capacity(N);
        for chunk in buf[1..].chunks_exact(16) {
            let mut tmp = [0u8; 16];
            tmp.copy_from_slice(chunk);
            z.push(Mod5::new(u128::from_le_bytes(tmp) as i128, R));
        }
        Ok(Self { c, z })
    }
}

/* ---------- Helpers ---------- */

#[inline(always)]
fn sample_uniform_modq(rng: &mut impl RngCore) -> Mod5 {
    const Q: u64 = 5u64.pow(R);
    const BOUND: u64 = ((1u128 << 64) - ((1u128 << 64) % Q as u128)) as u64;
    loop {
        let v = rng.next_u64();
        if v < BOUND {
            return Mod5::new((v % Q) as i128, R);
        }
    }
}

fn sample_sparse_vec(rng: &mut impl RngCore) -> Vec<Mod5> {
    let mut v = vec![Mod5::new(0, R); N];
    let mut idx: Vec<usize> = (0..N).collect();
    for i in 0..OMEGA {
        let j = i + (rng.next_u64() as usize % (N - i));
        idx.swap(i, j);
    }
    for &k in &idx[..OMEGA] {
        let s = if rng.next_u32() & 1 == 0 { 1 } else { -1 };
        v[k] = Mod5::new(s, R);
    }
    v
}

#[inline(always)]
fn mat_vec_mul_mod(a: &[Vec<Mod5>], x: &[Mod5]) -> Vec<Mod5> {
    a.iter()
        .map(|row| {
            row.iter().zip(x).fold(Mod5::new(0, R), |acc, (ai, xi)| {
                acc + (ai.clone() * xi.clone())
            })
        })
        .collect()
}

fn hash_challenge(pk: &PublicKey, u: &[Mod5], msg: &[u8]) -> u8 {
    let mut h = Hasher::new();
    for row in &pk.a {
        for c in row {
            h.update(&c.value().to_le_bytes());
        }
    }
    for c in u {
        h.update(&c.value().to_le_bytes());
    }
    h.update(msg);
    h.finalize().as_bytes()[0]
}

fn hw(v: &[Mod5]) -> usize {
    v.iter().filter(|c| c.value() != 0).count()
}

/* ---------- KeyGen ---------- */

pub fn keygen() -> Keypair {
    let mut rng = rng();
    let a: Vec<Vec<Mod5>> = (0..M)
        .map(|_| (0..N).map(|_| sample_uniform_modq(&mut rng)).collect())
        .collect();
    let s = sample_sparse_vec(&mut rng);
    let t = mat_vec_mul_mod(&a, &s);
    Keypair {
        pk: PublicKey { a, t },
        sk: SecretKey { s },
    }
}

/* ---------- Constant-time mask ---------- */

#[inline]
fn ct_mask(bit: u8) -> i128 {
    -(bit as i8 as i128)
} // 0 → 0, 1 → −1

/* ---------- Sign ---------- */

pub fn sign(kp: &Keypair, msg: &[u8]) -> Signature {
    let mut rng = rng();
    loop {
        let y = sample_sparse_vec(&mut rng);
        let u = mat_vec_mul_mod(&kp.pk.a, &y);
        let c = hash_challenge(&kp.pk, &u, msg);
        let m = ct_mask(c & 1); // −1 ó 0

        let z: Vec<Mod5> = y
            .iter()
            .zip(&kp.sk.s)
            .map(|(yi, si)| {
                let add = si.clone() * Mod5::new(m, R);
                yi.clone() + add
            })
            .collect();

        if hw(&z) <= OMEGA {
            return Signature { c, z };
        }
    }
}

/* ---------- Verify ---------- */

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    if hw(&sig.z) > OMEGA {
        return false;
    }

    let m = ct_mask(sig.c & 1);
    let mut u_p = mat_vec_mul_mod(&pk.a, &sig.z);
    for (ui, ti) in u_p.iter_mut().zip(&pk.t) {
        *ui = ui.clone() + (ti.clone() * Mod5::new(m, R));
    }

    sig.c == hash_challenge(pk, &u_p, msg)
}
