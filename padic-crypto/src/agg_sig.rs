//! Firma agregada p-TSig (Tier-A Compact) – Sprint D-1
//!
//! • 1 ≤ k ≤ 16 firmantes.
//! • Todas las firmas deben ser sobre el *mismo mensaje* **y** compartir el mismo
//!   desafío `c` (modelo “commit-reveal” con lista de `uᵢ`).
//! • `aggregate()` ya comprueba `c` y suma los vectores `z`.
//! • `verify_agg()` se implementará en Sprint D-2.
//

#![deny(warnings)]

use crate::sign_compact::{PublicKey, Signature, R};
use padic_core::mod5::Mod5;

/* ---------- Tipo principal ---------- */

/// Firma agregada:
/// * `z_sum`  – Σ zᵢ  (vector longitud N, coef   mod 5ᴿ)
/// * `c`      – reto único                   (u8)
/// * `u_list` – lista de compromisos `uᵢ = A·yᵢ` (k × M vectores)
#[derive(Clone, Debug)]
pub struct AggregateSig {
    pub z_sum: Vec<Mod5>,
    pub c: u8,
    pub u_list: Vec<Vec<Mod5>>,
}

/* ---------- Agregación ---------- */

/// Agrupa 1‒16 firmas individuales **con el mismo `c`**.
///
/// Paniquea si:
/// • la lista está vacía o tiene >16 firmas;  
/// • los `c` no coinciden;  
/// • las longitudes de `z` o `u` difieren.
///
/// Suma cada coordenada `z` módulo 5ʳ.
pub fn aggregate(sigs: &[Signature], u_list: &[Vec<Mod5>]) -> AggregateSig {
    assert!(
        (1..=16).contains(&sigs.len()) && sigs.len() == u_list.len(),
        "p-TSig needs 1‒16 firmas y lista u del mismo tamaño"
    );

    let c0 = sigs[0].c;
    let z_len = sigs[0].z.len();
    let u_len = u_list[0].len();

    let mut z_sum = vec![Mod5::new(0, R); z_len];

    for (sig, u) in sigs.iter().zip(u_list) {
        assert_eq!(sig.c, c0, "todos los `c` deben coincidir");
        assert_eq!(sig.z.len(), z_len, "longitud de z desigual");
        assert_eq!(u.len(), u_len, "longitud de u desigual");

        for (acc, zi) in z_sum.iter_mut().zip(&sig.z) {
            *acc = acc.clone() + zi.clone();
        }
    }

    AggregateSig {
        z_sum,
        c: c0,
        u_list: u_list.to_vec(),
    }
}

/* ---------- Verificación agregada (pendiente) ---------- */

/// Verifica la firma agregada contra las claves públicas y el mensaje.
///
/// *Por completar en Sprint D-2.*
pub fn verify_agg(_pks: &[PublicKey], _agg: &AggregateSig, _msg: &[u8]) -> bool {
    todo!("implement in Sprint D-2")
}
