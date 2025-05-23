use criterion::{criterion_group, criterion_main, Criterion};
use padic_core::mod5::Mod5;

fn bench_add(c: &mut Criterion) {
    let a = Mod5::new(123456, 10);
    let b = Mod5::new(654321, 10);
    c.bench_function("add_mod5", |bencher| {
        bencher.iter(|| {
            let _ = a.clone() + b.clone();
        })
    });
}

criterion_group!(benches, bench_add);
criterion_main!(benches);
