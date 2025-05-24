#![deny(warnings)]

//! π SIS batch – Halo 2 scaffold (v0.3) con gates mínimas.

use crate::agg_sig::AggregateSig;
use crate::sign_compact::PublicKey;
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

/* ---------- helpers ---------- */

const Q_I128: i128 = 244_140_625; // 5¹²

fn to_scalar(x: i128) -> Scalar {
    let mut v = x % Q_I128;
    if v < 0 {
        v += Q_I128;
    }
    Scalar::from(v as u64)
}

impl PiSISCircuit {
    /// Construye el circuito a partir de la firma agregada y los PK.
    pub fn from_aggregate(
        agg: &AggregateSig,
        pks: &[PublicKey],
        _msg: &[u8], // todavía sin usar
    ) -> Self {
        /* 1) w = concatenación de z  (de momento usamos z_sum como stub) */
        let w: Vec<Scalar> = agg
            .z_sum
            .iter()
            .map(|z| to_scalar(z.value() as i128))
            .collect();

        /* 2) b = 1 si wᵢ ≠ 0 */
        let b: Vec<Scalar> = w
            .iter()
            .map(|coef| {
                if *coef == Scalar::zero() {
                    Scalar::zero()
                } else {
                    Scalar::one()
                }
            })
            .collect();

        /* 3) m = coeficientes de M = [A₁‖…‖A_k] */
        let mut m = Vec::<Scalar>::new();
        for pk in pks {
            for row in &pk.a {
                for coef in row {
                    m.push(to_scalar(coef.value() as i128));
                }
            }
        }

        /* 4) u = Σuᵢ + m·Σtᵢ */
        let rows = pks[0].t.len(); // 93
        let m_factor: i128 = if agg.c & 1 == 1 { -1 } else { 0 };
        let mut acc = vec![0_i128; rows];

        for (pk, u_vec) in pks.iter().zip(&agg.u_list) {
            for j in 0..rows {
                let val = u_vec[j].value() as i128 + m_factor * pk.t[j].value() as i128;
                acc[j] += val;
            }
        }
        let u: Vec<Scalar> = acc.into_iter().map(to_scalar).collect();

        Self { w, b, m, u }
    }
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
