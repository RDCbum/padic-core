#![deny(warnings)]

use halo2_proofs::dev::MockProver;
use padic_crypto::{
    agg_sig::aggregate,
    proof::PiSISCircuit,
    sign_compact::{keygen, mat_vec_mul_mod, sign},
};

const M: usize = 93;
const N: usize = 109;

#[test]
fn proof_constraints_hold() {
    let msg = b"halo2 mock test";

    /* ---------- generar dos firmantes con mismo reto par ---------- */

    let kp1 = keygen();
    let kp2 = keygen();

    let sig1 = sign(&kp1, msg);
    let mut sig2;
    loop {
        sig2 = sign(&kp2, msg);
        if sig2.c == sig1.c && (sig1.c & 1) == 0 {
            break;
        }
    }

    /* ---------- calcular uᵢ = A·zᵢ ---------- */
    let u1 = mat_vec_mul_mod(&kp1.pk.a, &sig1.z);
    let u2 = mat_vec_mul_mod(&kp2.pk.a, &sig2.z);

    let agg = aggregate(&[sig1, sig2], &[u1.clone(), u2.clone()]);

    /* ---------- circuito ---------- */
    let circuit = PiSISCircuit::from_aggregate(&agg, &[kp1.pk.clone(), kp2.pk.clone()], msg);

    /* ---------- elegir k ---------- */
    let rows_needed = (agg.u_list.len() * M * N) as u32;
    let mut k = 10;
    while (1u32 << k) < rows_needed {
        k += 1;
    }

    /* ---------- MockProver ---------- */
    let prover = MockProver::run(k, &circuit, vec![circuit.u.clone()]).unwrap();
    prover.assert_satisfied();
}
