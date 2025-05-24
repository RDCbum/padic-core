#![deny(warnings)]

// Reexportaremos las primitivas aquí más adelante
pub mod agg_sig;
pub mod enc_core;
pub mod error;
pub mod fo;
pub mod kem_compact;
pub mod proof;
pub mod sampler;
pub mod sign_compact; // π SIS batch Halo 2

// --- ← aquí ya no hay nada más --- //
