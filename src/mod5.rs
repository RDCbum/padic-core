use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// Enteros módulo 5^r.
/// – `value` siempre está en `[0, modulus)`.
/// – `modulus = 5^r`, se pre-calcula y se guarda para evitar recomputarlo.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mod5 {
    value: u128,
    r: u32,
    modulus: u128,
}

impl Mod5 {
    /// Crea un nuevo número módulo 5^r a partir de `value`.
    pub fn new(value: i128, r: u32) -> Self {
        let modulus = 5u128.pow(r);
        // Convertimos a rango positivo antes de reducir.
        let val = ((value % modulus as i128) + modulus as i128) as u128 % modulus;
        Self { value: val, r, modulus }
    }

    /// Devuelve el valor reducido (útil para tests o debug).
    #[allow(dead_code)]
    pub fn value(&self) -> u128 {
        self.value
    }

    /// Devuelve r.
    #[allow(dead_code)]
    pub fn r(&self) -> u32 {
        self.r
    }

    /// Devuelve 5^r.
    #[allow(dead_code)]
    pub fn modulus(&self) -> u128 {
        self.modulus
    }

    /// Suma (self + other) mod 5^r.
    pub fn add_mod(&self, other: &Self) -> Self {
        assert_eq!(self.r, other.r, "mismatched r");
        Mod5::new((self.value + other.value) as i128, self.r)
    }

    /// Resta (self − other) mod 5^r.
    pub fn sub_mod(&self, other: &Self) -> Self {
        assert_eq!(self.r, other.r, "mismatched r");
        Mod5::new(self.value as i128 - other.value as i128, self.r)
    }

    /// Producto (self · other) mod 5^r.
    pub fn mul_mod(&self, other: &Self) -> Self {
        assert_eq!(self.r, other.r, "mismatched r");
        Mod5::new((self.value * other.value) as i128, self.r)
    }
}

/* ---------- Trait impls ---------- */

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
        *self = self.add_mod(&rhs);
    }
}

impl Sub for Mod5 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        self.sub_mod(&rhs)
    }
}

impl<'a> Sub<&'a Mod5> for Mod5 {
    type Output = Self;
    fn sub(self, rhs: &'a Mod5) -> Self::Output {
        self.sub_mod(rhs)
    }
}

impl SubAssign for Mod5 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub_mod(&rhs);
    }
}

impl Mul for Mod5 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        self.mul_mod(&rhs)
    }
}

impl<'a> Mul<&'a Mod5> for Mod5 {
    type Output = Self;
    fn mul(self, rhs: &'a Mod5) -> Self::Output {
        self.mul_mod(rhs)
    }
}

impl MulAssign for Mod5 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul_mod(&rhs);
    }
}

/* ---------- Tests ---------- */

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_mod() {
        let r = 3;
        let m = 5u128.pow(r);
        let a = Mod5::new(m as i128 + 2, r);
        let b = Mod5::new(m as i128 + 3, r);
        let c = a + b;
        assert_eq!(c.value(), (2 + 3) % m);
    }

    #[test]
    fn test_sub_mod() {
        let r = 4;
        let m = 5u128.pow(r);
        let a = Mod5::new(3, r);
        let b = Mod5::new(7, r);
        let c = a - b; // 3 − 7 ≡ m−4
        assert_eq!(c.value(), (m + 3 - 7) % m);
    }

    #[test]
    fn test_mul_mod() {
        let r = 2;
        let m = 5u128.pow(r);
        let a = Mod5::new(6, r);
        let b = Mod5::new(9, r);
        let c = a * b;
        assert_eq!(c.value(), (6 * 9) % m);
    }
}