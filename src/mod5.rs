#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mod5 {
    value: i64,
    r: u32,
}

impl Mod5 {
    pub fn new(value: i64, r: u32) -> Self {
        let modulus = 5_i64.pow(r);
        let mut val = value % modulus;
        if val < 0 {
            val += modulus;
        }
        Self { value: val, r }
    }

    pub fn value(&self) -> i64 {
        self.value
    }

    pub fn modulus(&self) -> i64 {
        5_i64.pow(self.r)
    }

    pub fn add_mod(&self, other: &Self) -> Self {
        assert_eq!(self.r, other.r, "mismatched r");
        Mod5::new(self.value + other.value, self.r)
    }
}

use std::ops::{Add, AddAssign};

impl Add for Mod5 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add_mod(&rhs)
    }
}

impl<'a> Add<&'a Mod5> for Mod5 {
    type Output = Self;

    fn add(self, rhs: &'a Mod5) -> Self::Output {
        self.add_mod(rhs)
    }
}

impl AddAssign for Mod5 {
    fn add_assign(&mut self, rhs: Self) {
        assert_eq!(self.r, rhs.r, "mismatched r");
        *self = Mod5::new(self.value + rhs.value, self.r);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_mod() {
        let r = 3;
        let modulus = 5_i64.pow(r);
        let a = Mod5::new(modulus + 2, r);
        let b = Mod5::new(modulus + 3, r);
        let c = a.add_mod(&b);
        assert_eq!(c.value(), (2 + 3) % modulus);
    }

    #[test]
    fn test_add_trait() {
        let r = 2;
        let a = Mod5::new(9, r);
        let b = Mod5::new(17, r);
        let c = a + b;
        assert_eq!(c.value(), 1);
    }
}
