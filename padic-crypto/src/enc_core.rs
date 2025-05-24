#![deny(warnings)]

use padic_core::Mod5;
use rand::{CryptoRng, RngCore};

use crate::kem_compact::Q;
use crate::kem_compact::{PublicKey, N};
use crate::sampler::{sample_error, uniform_u128};

const R_PARAM: u32 = 12;

fn dot(a: &[Mod5], b: &[Mod5]) -> Mod5 {
    a.iter().zip(b).fold(Mod5::new(0, R_PARAM), |acc, (x, y)| {
        acc + x.clone() * y.clone()
    })
}

pub fn enc_core<R: RngCore + CryptoRng + ?Sized>(
    pk: &PublicKey,
    rng: &mut R,
) -> (Vec<Mod5>, Mod5, Vec<Mod5>, Vec<i8>) {
    let r: Vec<Mod5> = (0..N)
        .map(|_| Mod5::new(uniform_u128(rng, Q) as i128, R_PARAM))
        .collect();

    let e: Vec<i8> = (0..N).map(|_| sample_error(rng)).collect();

    let u: Vec<Mod5> =
        pk.a.iter()
            .enumerate()
            .map(|(i, row)| {
                let mut acc = dot(row, &r);
                acc += Mod5::new(e[i] as i128, R_PARAM);
                acc
            })
            .collect();

    let v = dot(&pk.t, &r);

    (u, v, r, e)
}
