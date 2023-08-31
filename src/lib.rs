pub use guest::attestation::certs::{
    CertFormat, get_kds_ark_ask_certs,
    get_kds_ark_ask_certs_and_validate, get_kds_ark_ask_certs_bytes, KdsCertificates,
    PRODUCT_NAME_MILAN,
    validate_ark_ask_vcek_certs,
};
pub use guest::attestation::get_report::Requester;
pub use guest::attestation::report::{
    AttestationReport, BuildVersion, Signature, TcbVersion,
};
pub use guest::attestation::verify::{
    Policy, Verification,
};
pub use guest::identity::{
    BlockSigner, create_identity_block, FamilyId, fingerprint_id_key, fingerprint_id_key_as_hex, IdAuthInfo,
    IdBlock, ImageId, LaunchDigest, ToBase64,
};
pub use guest::measure::calc_launch_digest;
pub use guest::measure::types::SevMode;
pub use guest::measure::vcpu_types::CpuType;

pub mod error;
pub mod common;
pub mod guest;