#![deny(warnings)]

use padic_crypto::proof::{prove, setup_params, verify, PiSISCircuit};

#[test]
fn proof_stub_compiles() {
    // Parámetros KZG placeholder
    let params = setup_params();

    // Circuito vacío (witness = [])
    let circuit = PiSISCircuit { w: Vec::new() };

    // Genera prueba vacía y la verifica
    let proof = prove(&params, &circuit);
    assert!(verify(&params, &proof));
}
