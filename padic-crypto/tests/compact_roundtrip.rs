//! Test de integración: round-trip KEM Compact (stub)
//!
//! Objetivo: comprobar que `encaps` y `decaps` producen
//! la misma clave compartida con la implementación provisional.

use padic_crypto::kem_compact;

#[test]
fn compact_roundtrip_stub() {
    // 1. Generamos claves
    let (pk, sk) = kem_compact::keygen();

    // 2. Encapsulamos usando la clave pública
    let (ct, ss_enc) = kem_compact::encaps(&pk);

    // 3. Desencapsulamos con la clave secreta
    let ss_dec = kem_compact::decaps(&ct, &sk, &pk);

    // 4. Deben coincidir
    assert_eq!(
        ss_enc, ss_dec,
        "El shared secret obtenido en decaps no coincide con el de encaps"
    );
}
