//! Firma MSIS Compact – Sprint C-2 (sign & verify reales)

use blake3::Hasher;
use padic_core::mod5::Mod5;
use rand::{rng, RngCore};

/* ---------- Constantes Tier-Compact ---------- */

pub const R: u32 = 12; // trabajamos mod 5¹²
pub const N: usize = 109;
pub const M: usize = 93;
pub const OMEGA: usize = 47;

/* ---------- Tipos públicos ---------- */

#[derive(Clone, Debug)]
pub struct PublicKey {
    pub a: Vec<Vec<Mod5>>, // M×N
    pub t: Vec<Mod5>,      // M
}

#[derive(Clone, Debug)]
pub struct SecretKey {
    pub s: Vec<Mod5>, // N
}

#[derive(Clone, Debug)]
pub struct Keypair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}

/// Firma = (c, z) con c ∈ [0,255] y peso(z) ≤ Ω
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub c: u8, // se usa sólo su bit 0
    pub z: Vec<Mod5>,
}

/* ---------- Helpers ---------- */

fn sample_uniform_modq(rng: &mut impl RngCore) -> Mod5 {
    const Q: u64 = 5u64.pow(R);
    const TWO64: u128 = 1u128 << 64;
    const BOUND: u64 = (TWO64 - (TWO64 % Q as u128)) as u64;
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
        let sign = if rng.next_u32() & 1 == 0 { 1 } else { -1 };
        v[k] = Mod5::new(sign, R);
    }
    v
}

fn mat_vec_mul_mod(a: &[Vec<Mod5>], x: &[Mod5]) -> Vec<Mod5> {
    a.iter()
        .map(|row| {
            row.iter().zip(x).fold(Mod5::new(0, R), |acc, (ai, xi)| {
                acc + (ai.clone() * xi.clone())
            })
        })
        .collect()
}

/// H(pk‖u‖msg) → primer byte como desafío (0-255).
fn hash_challenge(pk: &PublicKey, u: &[Mod5], msg: &[u8]) -> u8 {
    let mut h = Hasher::new();
    for row in &pk.a {
        for coef in row {
            h.update(&coef.value().to_le_bytes());
        }
    }
    for coef in u {
        h.update(&coef.value().to_le_bytes());
    }
    h.update(msg);
    let digest: [u8; 32] = h.finalize().into();
    digest[0] // byte completo
}

fn hamming_weight(v: &[Mod5]) -> usize {
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

/* ---------- Firmar ---------- */

pub fn sign(kp: &Keypair, msg: &[u8]) -> Signature {
    let mut rng = rng();
    loop {
        let y = sample_sparse_vec(&mut rng);
        let u = mat_vec_mul_mod(&kp.pk.a, &y);

        let c_byte = hash_challenge(&kp.pk, &u, msg);
        let bit0 = c_byte & 1;

        let z: Vec<Mod5> = y
            .iter()
            .zip(&kp.sk.s)
            .map(|(yi, si)| {
                if bit0 == 1 {
                    yi.clone() + si.clone()
                } else {
                    yi.clone()
                }
            })
            .collect();

        if hamming_weight(&z) <= OMEGA {
            return Signature { c: c_byte, z };
        }
    }
}

/* ---------- Verificar ---------- */

pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    if hamming_weight(&sig.z) > OMEGA {
        return false;
    }

    let bit0 = sig.c & 1;
    let mut u_prime = mat_vec_mul_mod(&pk.a, &sig.z);
    if bit0 == 1 {
        for (ui, ti) in u_prime.iter_mut().zip(&pk.t) {
            *ui = ui.clone() - ti.clone();
        }
    }

    let c_prime = hash_challenge(pk, &u_prime, msg);
    sig.c == c_prime
}
