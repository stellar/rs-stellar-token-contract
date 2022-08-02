#![no_std]

#[cfg(any(test, feature = "testutils"))]
#[macro_use]
extern crate std;

mod admin;
mod allowance;
mod balance;
mod contract;
pub mod cryptography;
mod metadata;
pub mod nonce;
pub mod public_types;
mod storage_types;
pub mod testutils;

pub use crate::contract::allowance::invoke as allowance;
pub use crate::contract::approve::invoke as approve;
pub use crate::contract::balance::invoke as balance;
pub use crate::contract::burn::invoke as burn;
pub use crate::contract::decimals::invoke as decimals;
pub use crate::contract::freeze::invoke as freeze;
pub use crate::contract::initialize::invoke as initialize;
pub use crate::contract::is_frozen::invoke as is_frozen;
pub use crate::contract::mint::invoke as mint;
pub use crate::contract::name::invoke as name;
pub use crate::contract::nonce::invoke as nonce;
pub use crate::contract::set_admin::invoke as set_admin;
pub use crate::contract::symbol::invoke as symbol;
pub use crate::contract::unfreeze::invoke as unfreeze;
pub use crate::contract::xfer::invoke as xfer;
pub use crate::contract::xfer_from::invoke as xfer_from;
