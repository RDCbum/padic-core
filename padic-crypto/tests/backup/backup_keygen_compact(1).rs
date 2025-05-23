use padic_crypto::{kem_compact, sign_compact};

#[test]
fn keygen_compact_sizes() {
    let (pk, sk) = kem_compact::keygen();
    assert_eq!(pk.0.len(), 109);
    assert_eq!(sk.0.len(), 109);

    let kp = sign_compact::keygen();
    assert_eq!(kp.pk.0.len(), 109);
}
