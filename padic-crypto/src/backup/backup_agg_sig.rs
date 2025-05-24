//! Firma agregada p-TSig (Tier-A Compact) – Sprint D-1
//!
//! • Soporta de 1 a 16 firmantes.
//! • Todas las firmas deben compartir el mismo mensaje **y el mismo desafío `c`**.
//! • `aggregate()` ya suma los vectores `z` y comprueba la igualdad de `c`.
//! • `verify_agg()` se implementará en Sprint D-2.

#![deny(warnings)]

use crate::sign_compact::{PublicKey, Signature, R};
use padic_core::mod5::Mod5;

/* ---------- Tipo principal ---------- */

/// Firma agregada: vector `z` sumado y desafío único `c`.
#[derive(Clone, Debug)]
pub struct AggregateSig {
    pub z_sum: Vec<Mod5>,
    pub c: u8,
}

/* ---------- Agregación ---------- */

/// Agrupa 1‒16 firmas individuales con **el mismo** `c`.
///
/// Paniquea si:
/// * la lista está vacía o tiene más de 16 firmas;
/// * algún `c` difiere;
/// * las longitudes de `z` no coinciden.
///
/// Suma cada coordenada `z` módulo 5ʳ usando los traits de `Mod5`.
pub fn aggregate(sigs: &[Signature]) -> AggregateSig {
    assert!(
        (1..=16).contains(&sigs.len()),
        "p-TSig supports 1..=16 signatures"
    );

    let c0 = sigs[0].c;
    let z_len = sigs[0].z.len();

    let mut z_sum = vec![Mod5::new(0, R); z_len];

    for sig in sigs {
        assert_eq!(sig.c, c0, "signatures must share the same challenge c");
        assert_eq!(sig.z.len(), z_len, "z length mismatch");

        for (acc, zi) in z_sum.iter_mut().zip(&sig.z) {
            *acc = acc.clone() + zi.clone();
        }
    }

    AggregateSig { z_sum, c: c0 }
}

/* ---------- Verificación agregada (pendiente) ---------- */

/// Verifica la firma agregada contra las claves públicas y el mensaje.
///
/// **Pendiente:** se completará en Sprint D-2.
pub fn verify_agg(_pks: &[PublicKey], _agg: &AggregateSig, _msg: &[u8]) -> bool {
    todo!("implement in Sprint D-2")
}
