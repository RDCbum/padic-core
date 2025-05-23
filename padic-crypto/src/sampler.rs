#![deny(warnings)]

use crate::kem_compact::Q;
use rand_core::{CryptoRng, RngCore};

/// Generate a uniform random `u128` in `[0, Q)` using rejection sampling.
pub fn uniform_u128<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> u128 {
    loop {
        let val = rng.next_u32() as u128;
        if val < Q {
            return val;
        }
    }
}

/// Sample from the error distribution { -2, -1, 0, 1, 2 } with equal probability.
pub fn sample_error<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> i8 {
    const TABLE: [i8; 5] = [-2, -1, 0, 1, 2];
    loop {
        let v = rng.next_u32();
        let range = u32::MAX - (u32::MAX % 5);
        if v < range {
            return TABLE[(v % 5) as usize];
        }
    }
}
