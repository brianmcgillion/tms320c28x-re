// SPDX-License-Identifier: MIT
//! TMS320C28x instruction decoder, operand model and COFF reader.
//!
//! Deliberately free of any Binary Ninja dependency: the plugin in `rust/`
//! re-exports these modules, and `c28x-tools` exposes them to pytest and CI
//! without a licence.

pub mod coff;
pub mod decoder;
pub mod operands;
pub mod text;
pub mod types;
