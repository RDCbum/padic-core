use crate::kem_compact::{keygen as kem_keygen, PublicKey, SecretKey};
use blake3::Hasher;
use padic_core::mod5::Mod5;

// ───────────── 2 constantes para el Tier-Compact ─────────────
const R: u32 = 12; // 5¹² ≃ 2,44×10⁸
const CHUNK: usize = 8; // 8 bytes → i64 → i128 → Mod5

pub struct Keypair {
    pub pk: PublicKey,
    pub sk: SecretKey,
}
pub struct Signature(pub Vec<Mod5>);

pub fn keygen() -> Keypair {
    let (pk, sk) = kem_keygen();
    Keypair { pk, sk }
}

/*────────────────────────── sign() ──────────────────────────*/
pub fn sign(_sk: &SecretKey, msg: &[u8]) -> Signature {
    // La clave _sk aún no se usa: esta es la versión “hash-as-signature”
    let mut h = Hasher::new();
    h.update(msg);
    let digest = h.finalize(); // 32 bytes

    // Hash → 4 coeficientes Mod5
    let coeffs: Vec<Mod5> = digest
        .as_bytes()
        .chunks(CHUNK) // 4 trozos de 8 B
        .map(|chunk| {
            let mut buf16 = [0u8; 16]; // ampliar a 16 B LE
            buf16[..chunk.len()].copy_from_slice(chunk);
            let val = i128::from_le_bytes(buf16);
            Mod5::new(val, R)
        })
        .collect();

    Signature(coeffs)
}

/*───────────────────────── verify() ─────────────────────────*/
pub fn verify(_pk: &PublicKey, msg: &[u8], sig: &Signature) -> bool {
    // _pk aún sin usar (stub). Re-hasheamos y comparamos.
    let mut h = Hasher::new();
    h.update(msg);
    let digest = h.finalize();

    let expected: Vec<Mod5> = digest
        .as_bytes()
        .chunks(CHUNK)
        .map(|chunk| {
            let mut buf16 = [0u8; 16];
            buf16[..chunk.len()].copy_from_slice(chunk);
            let val = i128::from_le_bytes(buf16);
            Mod5::new(val, R)
        })
        .collect();

    sig.0 == expected
}
