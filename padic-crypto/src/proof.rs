#![deny(warnings)]

//! π SIS batch – Halo 2 scaffold (v0.3) con gates mínimas.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    pasta::pallas,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation, // ← Rotation está en el módulo poly
};

pub type Scalar = pallas::Scalar;

/* ---------- Circuit & Config ---------- */

#[derive(Clone, Debug)]
pub struct PiSISCircuit {
    pub w: Vec<Scalar>, // coeficientes z concatenados (k·N)
    pub b: Vec<Scalar>, // bits presencia
    pub m: Vec<Scalar>, // coeficientes matriz M
    pub u: Vec<Scalar>, // instancia pública
}

#[derive(Clone, Debug)]
pub struct PiSISConfig {
    col_w: Column<Advice>,
    col_b: Column<Advice>,
    col_m: Column<Fixed>,
    col_q: Selector,
    _col_u: Column<Instance>, // aún no usado
}

impl PiSISConfig {
    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self {
        let col_w = meta.advice_column();
        let col_b = meta.advice_column();
        let col_m = meta.fixed_column();
        let col_q = meta.selector();
        let col_u = meta.instance_column();

        /* Gate 1: q·(m·w − u) = 0 */
        meta.create_gate("row equality", |meta| {
            let q = meta.query_selector(col_q);
            let m = meta.query_fixed(col_m);
            let w = meta.query_advice(col_w, Rotation::cur());
            let u = meta.query_instance(col_u, Rotation::cur());
            vec![q * (m * w - u)]
        });

        /* Gate 2: b booleano */
        meta.create_gate("b boolean", |meta| {
            let b = meta.query_advice(col_b, Rotation::cur());
            let one = Expression::Constant(Scalar::one());
            vec![b.clone() * (one - b)]
        });

        /* Gate 3: (1−b)·w = 0 */
        meta.create_gate("link w/b", |meta| {
            let b = meta.query_advice(col_b, Rotation::cur());
            let w = meta.query_advice(col_w, Rotation::cur());
            let one = Expression::Constant(Scalar::one());
            vec![(one - b) * w]
        });

        Self {
            col_w,
            col_b,
            col_m,
            col_q,
            _col_u: col_u,
        }
    }
}

impl Circuit<Scalar> for PiSISCircuit {
    type Config = PiSISConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            w: vec![Scalar::zero(); self.w.len()],
            b: vec![Scalar::zero(); self.b.len()],
            m: self.m.clone(),
            u: self.u.clone(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<Scalar>) -> Self::Config {
        PiSISConfig::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Scalar>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "assign rows",
            |mut region| {
                let rows = self.m.len();
                for offset in 0..rows {
                    config.col_q.enable(&mut region, offset)?;

                    let w_val = *self.w.get(offset).unwrap_or(&Scalar::zero());
                    let b_val = *self.b.get(offset).unwrap_or(&Scalar::zero());
                    let m_val = *self.m.get(offset).unwrap_or(&Scalar::zero());

                    region.assign_advice(|| "w", config.col_w, offset, || Value::known(w_val))?;
                    region.assign_advice(|| "b", config.col_b, offset, || Value::known(b_val))?;
                    region.assign_fixed(|| "m", config.col_m, offset, || Value::known(m_val))?;
                }
                Ok(())
            },
        )
    }
}

/* ---------- Parámetros y prueba (stubs) ---------- */

pub type HaloParams = ();

pub fn setup_params() -> HaloParams {
    ()
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct Proof(Vec<u8>);

pub fn prove(_: &HaloParams, _dummy_rows: usize) -> Proof {
    Proof(Vec::new())
}

pub fn verify(_: &HaloParams, _: &Proof) -> bool {
    true
}
