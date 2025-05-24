#![deny(warnings)]

use crate::kem_compact::{serialize_mod5_vec, PublicKey, N, Q, R_PARAM};
use blake3::Hasher;
use padic_core::Mod5;

/// Deriva `r` determinista = H(pk‖u‖v) → N coeficientes en ℤ_Q.
pub fn derive_r(pk: &PublicKey, u: &[Mod5], v: &Mod5) -> Vec<Mod5> {
    // 1) hash acumulativo
    let mut h = Hasher::new();
    h.update(&serialize_mod5_vec(&pk.t));
    for row in &pk.a {
        h.update(&serialize_mod5_vec(row));
    }
    h.update(&serialize_mod5_vec(u));
    h.update(&v.value().to_le_bytes());

    // 2) XOF expand
    let mut out = Vec::with_capacity(N);
    let mut counter: u32 = 0;
    while out.len() < N {
        let mut h_i = h.clone();
        h_i.update(&counter.to_le_bytes());
        let bytes = h_i.finalize();
        for chunk in bytes.as_bytes().chunks(16) {
            if out.len() == N {
                break;
            }
            let mut buf = [0u8; 16];
            buf[..chunk.len()].copy_from_slice(chunk);
            let val = u128::from_le_bytes(buf) % Q;
            out.push(Mod5::new(val as i128, R_PARAM));
        }
        counter += 1;
    }
    out
}
