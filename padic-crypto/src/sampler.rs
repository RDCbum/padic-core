//! Muestreadores para el KEM Compact

#![deny(warnings)]

use rand::{CryptoRng, RngCore};

/// Rechazo uniforme: devuelve `x ∈ [0, q)`
pub fn uniform_u128<R: RngCore + CryptoRng + ?Sized>(rng: &mut R, q: u128) -> u128 {
    assert!(q > 0, "q must be > 0");
    let zone = u128::MAX - (u128::MAX % q); // ← q se usa aquí
    loop {
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);
        let x = u128::from_le_bytes(buf);
        if x < zone {
            return x % q;
        }
    }
}

/// Error corto uniforme en `{-2,-1,0,1,2}`
pub fn sample_error<R: RngCore + CryptoRng + ?Sized>(rng: &mut R) -> i8 {
    uniform_u128(rng, 5) as i8 - 2
}
