#![deny(warnings)]

use padic_crypto::proof::{prove, setup_params, verify, Proof};

#[test]
fn proof_stub_compiles() {
    let params = setup_params();
    let proof: Proof = prove(&params, 0);
    assert!(verify(&params, &proof));
}
