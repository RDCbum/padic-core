use padic_core::mod5::Mod5; // ajusta ruta si hiciste módulo público
use proptest::prelude::*;

proptest! {
    // genera r de 1‥=10 y valores de 0‥5^r − 1
    #[test]
    fn prop_add_commutative(r in 1u32..=10, a in 0u128..1_000_000, b in 0u128..1_000_000) {
        let a = Mod5::new(a as i128, r);
        let b = Mod5::new(b as i128, r);
        prop_assert_eq!(a.clone() + b.clone(), b + a);
    }

    #[test]
    fn prop_mul_commutative(r in 1u32..=10, a in 0u128..1_000, b in 0u128..1_000) {
        let a = Mod5::new(a as i128, r);
        let b = Mod5::new(b as i128, r);
        prop_assert_eq!(a.clone() * b.clone(), b * a);
    }

    #[test]
    fn prop_distributive(r in 1u32..=8, a in 0u128..10_000, b in 0u128..10_000, c in 0u128..10_000) {
        let a = Mod5::new(a as i128, r);
        let b = Mod5::new(b as i128, r);
        let c = Mod5::new(c as i128, r);
        prop_assert_eq!(a.clone() * (b.clone() + c.clone()), (a.clone() * b) + (a * c));
    }
}
