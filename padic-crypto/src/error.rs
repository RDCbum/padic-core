//! Errores de (de)serialización binaria – sin dependencias externas.

#![deny(warnings)]
use core::fmt;

/// Falta longitud exacta; el buffer no encaja.
#[derive(Debug, Clone)]
pub enum DeserializeError {
    Length,
}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeserializeError::Length => write!(f, "input length mismatch"),
        }
    }
}

impl std::error::Error for DeserializeError {}
