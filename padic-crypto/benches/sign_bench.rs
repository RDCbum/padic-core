use criterion::{criterion_group, criterion_main, Criterion};
#[path = "util/bench_config.rs"]
mod bench_config;
use bench_config::default;

use padic_crypto::sign_compact::*;

fn bench_keygen(c: &mut Criterion) {
    c.bench_function("compact_keygen", |b| b.iter(|| keygen()));
}

fn bench_sign(c: &mut Criterion) {
    let kp = keygen();
    let msg = b"benchmark";
    c.bench_function("compact_sign", |b| b.iter(|| sign(&kp, msg)));
}

fn bench_verify(c: &mut Criterion) {
    let kp = keygen();
    let msg = b"benchmark";
    let sig = sign(&kp, msg);
    c.bench_function("compact_verify", |b| b.iter(|| verify(&kp.pk, msg, &sig)));
}

criterion_group! {
    name    = compact;
    config  = default();
    targets = bench_keygen, bench_sign, bench_verify
}
criterion_main!(compact);
