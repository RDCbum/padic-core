#![deny(warnings)]
use padic_crypto::proof::*;

#[test]
fn proof_stub_compiles() {
    let params = setup_params();
    let dummy_proof = prove(&padic_crypto::agg_sig::AggregateSig {
        z_sum: Vec::new(),
        c: 0,
        u_list: Vec::new(),
    });
    assert!(verify(&dummy_proof));
    let _ = params; // evita warning por ahora
}
