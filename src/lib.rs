#![feature(async_closure)]

pub mod error;
pub mod common;
pub mod guest;

pub use guest::attestation::report::{
    TcbVersion, BuildVersion, Signature, AttestationReport
};
pub use guest::attestation::verify::{
    Verification, Policy
};
pub use guest::attestation::certs::{
    KdsCertificates, CertFormat,
    get_kds_ark_ask_certs_bytes, get_kds_ark_ask_certs, get_kds_ark_ask_certs_and_validate,
    validate_ark_ask_vcek_certs,
    PRODUCT_NAME_MILAN
};