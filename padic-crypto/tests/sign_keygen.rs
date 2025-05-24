use padic_crypto::sign_compact::*;

#[test]
fn keygen_dimensions_and_weight() {
    let kp = keygen();
    assert_eq!(kp.pk.a.len(), M);
    assert_eq!(kp.pk.a[0].len(), N);
    assert_eq!(kp.sk.s.len(), N);
    assert_eq!(kp.pk.t.len(), M);

    let weight = kp.sk.s.iter().filter(|c| c.value() != 0).count();
    assert!(weight <= OMEGA);
}
