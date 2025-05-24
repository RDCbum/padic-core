#![allow(dead_code)]

use criterion::Criterion;
use std::time::Duration;

pub fn default() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(6))
        .sample_size(60)
}
