//! KEM Compact – stub de trabajo
//! ---------------------------------------------------------------
//!  - Dimensión fija N = 109
//!  - Módulo 5^R con R = 12
//!  - keygen(): vectores aleatorios de Mod5 (por ahora pk == sk)
//!  - encaps()/decaps(): round-trip provisional mediante BLAKE3
//!
//!  ⛔  ESTE CÓDIGO NO ES LA IMPLEMENTACIÓN MSIS FINAL.
//!      Sirve únicamente para validar la API y los flujos
//!      mientras desarrollamos el resto del ecosistema.

#![allow(clippy::redundant_clone)]

use padic_core::mod5::Mod5;
use rand::random;
use blake3;

pub const N: usize = 109;   // dimensión Compact
pub const R: u32   = 12;    // q = 5^12

/// Clave pública (stub): vector de `Mod5`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(pub Vec<Mod5>);

/// Clave secreta (stub): igual que `PublicKey` de momento.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey(pub Vec<Mod5>);

/// Ciphertext (stub): copia directa del `PublicKey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext(pub Vec<Mod5>);

/// Genera tupla `(pk, sk)` con vectores aleatorios.
/// Por ahora `pk` y `sk` son idénticos (suficiente para probar flujo).
pub fn keygen() -> (PublicKey, SecretKey) {
    let mut pk = Vec::with_capacity(N);
    let mut sk = Vec::with_capacity(N);

    for _ in 0..N {
        // 64 bits aleatorios → reducción mod 5^R
        let r = random::<u64>() as i128;
        let m = Mod5::new(r, R);
        pk.push(m.clone());
        sk.push(m);              // stub: pk == sk
    }

    (PublicKey(pk), SecretKey(sk))
}

/// `encaps` provisional:
///   1. Ciphertext = copia de `pk`.
///   2. shared_secret = BLAKE3(serialización ct).
pub fn encaps(pk: &PublicKey) -> (Ciphertext, [u8; 32]) {
    // 1) construir el ciphertext
    let ct = Ciphertext(pk.0.clone());

    // 2) serializar cada `Mod5` (u128 little-endian)
    let mut bytes = Vec::with_capacity(N * 16);
    for m in &ct.0 {
        bytes.extend_from_slice(&m.value().to_le_bytes());
    }

    // 3) shared_secret = hash(bytes)
    let hash = blake3::hash(&bytes);
    (ct, *hash.as_bytes())
}

/// `decaps` provisional:
///   Repite la misma serialización + hash -> misma clave.
pub fn decaps(ct: &Ciphertext, _sk: &SecretKey) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(N * 16);
    for m in &ct.0 {
        bytes.extend_from_slice(&m.value().to_le_bytes());
    }
    let hash = blake3::hash(&bytes);
    *hash.as_bytes()
}


