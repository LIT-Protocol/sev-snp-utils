extern crate core;

pub mod error;
pub mod common;
pub mod guest;

pub use guest::attestation::report::{
    TcbVersion, BuildVersion, Signature, AttestationReport
};