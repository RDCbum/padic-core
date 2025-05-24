//! Firma agregada p-TSig (Tier-A Compact) – **borrador inicial**.
//
//  • Diseñado para agregaciones de hasta 16 firmantes (c ∈ [0,255] → sum ≤ 4095).
//  • De momento las funciones devuelven `todo!()`; las rellenaremos en Sprint D-1/2.
//

#![deny(warnings)]

use crate::sign_compact::{PublicKey, Signature};
use padic_core::mod5::Mod5;

/// Suma de firmas MSIS Compact de varios validadores.
///
/// * `z_sum` = Σ zᵢ  (vector de longitud N mod 5ᴿ)  
/// * `c_sum` = Σ cᵢ  (entero pequeño; mientras sum ≤ 4095 cabe en `u16`)
#[derive(Clone, Debug)]
pub struct AggregateSig {
    pub z_sum: Vec<Mod5>,
    pub c_sum: u16,
}

/// Agrupa una lista de firmas individuales; todas deben compartir el mismo mensaje.
///
/// *No* hace todavía verificación ni constante-tiempo.
pub fn aggregate(_sigs: &[Signature]) -> AggregateSig {
    todo!("implement in Sprint D-1")
}

/// Verifica la firma agregada contra el vector de claves públicas y el mensaje.
///
/// Debe comprobar:
///   1. `len(pks) == len(sigs)`
///   2. Σ Hash(pkᵢ‖uᵢ‖msg) = c_sum   mod 256
///   3. Σ zᵢ  = z_sum                 (ya implícito)
///
/// Retorna `false` si hay cualquier fallo (peso, hash, etc.).
pub fn verify_agg(_pks: &[PublicKey], _agg: &AggregateSig, _msg: &[u8]) -> bool {
    todo!("implement in Sprint D-2")
}
