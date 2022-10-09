#![feature(async_closure)]

pub mod error;
pub mod common;
pub mod guest;

pub use guest::attestation::report::{
    TcbVersion, BuildVersion, Signature, AttestationReport
};
pub use guest::attestation::verify::Policy;