//! Stages and helpers that resolve [EIP-8288] transaction dependencies during derivation.
//!
//! [EIP-8288]: https://eips.ethereum.org/EIPS/eip-8288

mod gate;
pub use gate::DependencyGate;

mod scanner;

#[cfg(test)]
mod go_vectors;
#[cfg(test)]
mod test_utils;
pub use scanner::{DEPENDENCY_SCAN_BYTE_CAP, DependencyScanner, Responsible};
