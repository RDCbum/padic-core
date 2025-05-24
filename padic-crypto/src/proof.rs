#![deny(warnings)]

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Fixed, Instance},
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use halo2curves::pasta::{EqAffine, Fp as Scalar};

/* ---------- Circuit & Config ---------- */

#[derive(Clone, Debug)]
pub struct PiSISCircuit {
    pub w: Vec<Scalar>,
}

#[derive(Clone, Debug)]
pub struct PiSISConfig {
    pub w: Column<Advice>,
    pub m: Vec<Column<Fixed>>,
    pub u: Column<Instance>,
}

impl PiSISConfig {
    pub fn configure(meta: &mut ConstraintSystem<Scalar>, rows: usize) -> Self {
        let w = meta.advice_column();
        let u = meta.instance_column();
        let m: Vec<_> = (0..rows).map(|_| meta.fixed_column()).collect();

        meta.enable_equality(w);
        meta.enable_equality(u);
        for col in &m {
            meta.enable_equality(*col);
        }

        Self { w, m, u }
    }
}

impl Circuit<Scalar> for PiSISCircuit {
    type Config = PiSISConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            w: vec![Scalar::default(); self.w.len()],
        }
    }

    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
        PiSISConfig::configure(meta, 1) // stub: 1 fila fija
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Scalar>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "w advice",
            |mut region| {
                for (offset, val) in self.w.iter().enumerate() {
                    region.assign_advice(|| "w", config.w, offset, || Value::known(*val))?;
                }
                Ok(())
            },
        )
    }
}

/* ---------- Parámetros stub ---------- */

pub type HaloParams = (); // aún sin esquema de compromiso real

pub fn setup_params() -> HaloParams {
    () // placeholder
}

/* ---------- Prueba stub ---------- */

#[derive(Clone, Debug)]
pub struct Proof(Vec<u8>);

pub fn prove(_params: &HaloParams, _circuit: &PiSISCircuit) -> Proof {
    let transcript = Blake2bWrite::<_, EqAffine, Challenge255<EqAffine>>::init(Vec::new());
    Proof(transcript.finalize())
}

pub fn verify(_params: &HaloParams, _proof: &Proof) -> bool {
    let _ = Blake2bRead::<_, EqAffine, Challenge255<EqAffine>>::init(&_proof.0[..]);
    true
}

