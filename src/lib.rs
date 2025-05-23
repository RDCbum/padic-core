// src/lib.rs
pub mod mod5; // declara que existe "src/mod5.rs" y lo hace parte del crate

pub use mod5::Mod5; // (opcional) re-exporta Mod5 en la raíz: padic_core::Mod5
