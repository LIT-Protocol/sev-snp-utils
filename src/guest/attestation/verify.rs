use async_trait::async_trait;

#[cfg(not(test))]
use tracing::warn;

#[cfg(test)]
use std::println as warn;

use crate::error::Result;
use crate::guest::attestation::certs::KdsCertificates;
use crate::{error, AttestationReport};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(unused)]
pub struct Policy {
    require_no_debug: bool,
    require_no_ma: bool,
    require_no_smt: bool,
    require_id_key: bool,
    require_author_key: bool,
}

impl Policy {
    pub fn new(
        require_no_debug: bool,
        require_no_ma: bool,
        require_no_smt: bool,
        require_id_key: bool,
        require_author_key: bool,
    ) -> Self {
        Self {
            require_no_debug,
            require_no_ma,
            require_no_smt,
            require_id_key,
            require_author_key,
        }
    }

    pub fn permissive() -> Self {
        Self::new(false, false, false, false, false)
    }

    pub fn strict() -> Self {
        Self::new(true, true, false, true, true)
    }
}

#[async_trait]
pub trait Verification {
    async fn verify(&self, policy: Option<Policy>) -> Result<bool>;
}

#[async_trait]
impl Verification for AttestationReport {
    async fn verify(&self, policy: Option<Policy>) -> Result<bool> {
        // Verify cert chain
        self.verify_certs().await?;

        // Verify report signature
        if !verify_report_signature(self).await? {
            warn!("report ECDSA signature verification failed");

            return Ok(false);
        }
        // Custom (extra) verification
        if let Some(policy) = policy {
            if policy.require_no_debug && self.policy_debug_allowed() {
                warn!("failed policy check - debug enabled");

                return Ok(false);
            }
            if policy.require_no_ma && self.policy_ma_allowed() {
                warn!("failed policy check - MA enabled");

                return Ok(false);
            }
            if policy.require_no_smt && self.policy_smt_allowed() {
                warn!("failed policy check - SMT enabled");

                return Ok(false);
            }
            if policy.require_author_key && !self.author_key_digest_present() {
                warn!("failed policy check - author key not present");

                return Ok(false);
            }
            if policy.require_id_key && !self.id_key_digest_present() {
                warn!("failed policy check - id key not present");

                return Ok(false);
            }
        }

        Ok(true)
    }
}

async fn verify_report_signature(report: &AttestationReport) -> Result<bool> {
    let vcek_ec = report.get_kds_vcek_ec_key().await?;

    let sig = report.signature.to_ecdsa_sig().map_err(|e| {
        error::cert(Some(
            format!("failed to extract ECDSA sig: {:?}", e).to_string(),
        ))
    })?;

    Ok(sig
        .verify(report.sha384().as_slice(), &vcek_ec)
        .map_err(|e| {
            error::cert(Some(
                format!("report signature verification failed: {:?}", e).to_string(),
            ))
        })?)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;

    use crate::guest::attestation::report::AttestationReport;
    use crate::guest::attestation::verify::{Policy, Verification};

    const TEST_REPORT_BIN: &str = "resources/test/guest_report.bin";
    const TEST_REPORT_BAD_SIG_BIN: &str = "resources/test/guest_report_bad_sig.bin";

    #[tokio::test]
    async fn verify_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_REPORT_BIN);

        let report = AttestationReport::from_file(&test_file).unwrap();

        assert_eq!(report.sha384_hex(), "8ac02cb042d3909a0e67ecc8a89a4869d6838f0c243a5e4d417757d6c06d10ae15d84d2b728fe80a355792f671afd6b4");

        let res = report
            .verify(Some(Policy::permissive()))
            .await
            .expect("failed to call verify");

        assert_eq!(res, true);

        // Should fail due to missing id key
        let res = report
            .verify(Some(Policy::strict()))
            .await
            .expect("failed to call verify");

        assert_eq!(res, false);
    }

    #[tokio::test]
    async fn verify_bad_sig_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_REPORT_BAD_SIG_BIN);

        let report = AttestationReport::from_file(&test_file).unwrap();

        // Incorrect hash for signature.
        assert_eq!(report.sha384_hex(), "125a8e5748291b4d6ab719a28f72c9a9d28ce22b91af78fe627c29433eb03495f2cfcd4d67222abf05291f1bbf9455cd");

        let res = report.verify(None).await.expect("failed to call verify");

        assert_eq!(res, false);
    }
}
