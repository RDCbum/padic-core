//! π SIS batch – Halo 2 stub
//!
//! * Compila limpio con `#![deny(warnings)]`.
//! * Circuito y API reales se implementarán en las fases D-3.2 y D-3.3.

#![deny(warnings)]

/// Stub de la prueba: todavía no la generamos ni la usamos.
/// El atributo evita el warning “field 0 is never read”.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Proof(Vec<u8>);

/// Devuelve parámetros placeholder (más adelante usaremos ParamsKZG).
pub fn setup_params() {}

/// Genera una prueba vacía.
pub fn prove(_: &crate::agg_sig::AggregateSig) -> Proof {
    Proof(Vec::new())
}

/// Verifica la prueba (siempre true mientras es stub).
pub fn verify(_: &Proof) -> bool {
    true
}
