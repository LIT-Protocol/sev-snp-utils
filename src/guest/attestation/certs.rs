use async_std::fs;
use async_std::fs::File;
use async_std::io::WriteExt;
use async_trait::async_trait;
use bytes::Bytes;
use pkix::pem::PEM_CERTIFICATE;

use crate::AttestationReport;
use crate::common::cache::cache_dir_path;
use crate::common::fetch::fetch_url_cached;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
#[allow(dead_code)]
const KDS_DEV_CERT_SITE: &str = "https://kdsintfdev.amd.com";
#[allow(dead_code)]
const KDS_CEK: &str = "/cek/id/";
const KDS_VCEK: &str = "/vcek/v1/";
// KDS_VCEK/{product_name}/{hwid}?{tcb parameter list}
#[allow(dead_code)]
const KDS_VCEK_CERT_CHAIN: &str = "cert_chain";
// KDS_VCEK/{product_name}/cert_chain
#[allow(dead_code)]
const KDS_VCEK_CRL: &str = "crl";                // KDS_VCEK/{product_name}/crl"

pub(crate) const PRODUCT_NAME_MILAN: &str = "Milan";

pub(crate) const CACHE_PREFIX: &str = "certs";

pub(crate) const FETCH_ATTEMPTS: u8 = 5;
pub(crate) const FETCH_ATTEMPT_SLEEP_MS: u64 = 5000;

fn get_cache_suffix(product_name: &str, chip_id: &str) -> String {
    format!("{}/{}/{}", CACHE_PREFIX, product_name, chip_id)
}

fn get_vcek_cert_name_prefix(boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> String {
    format!("{:0>2}{:0>2}{:0>2}{:0>2}", boot_loader, tee, snp, microcode)
}

pub fn get_kds_vcek_der_url(product_name: &str, chip_id: &str,
                            boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> String {
    format!("{}{}{}/{}?blSPL={:0>2}&teeSPL={:0>2}&snpSPL={:0>2}&ucodeSPL={:0>2}",
            KDS_CERT_SITE, KDS_VCEK, product_name, chip_id, boot_loader, tee, snp, microcode)
}

pub async fn fetch_kds_vcek_der(product_name: &str, chip_id: &str,
                                boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> crate::error::Result<Bytes> {
    let save_path = format!("{}/{}.der",
                            get_cache_suffix(product_name, chip_id),
                            get_vcek_cert_name_prefix(boot_loader, tee, snp, microcode)
    );
    fetch_url_cached(
        get_kds_vcek_der_url(product_name, chip_id, boot_loader, tee, snp, microcode).as_str(),
        save_path.as_str(), FETCH_ATTEMPTS, FETCH_ATTEMPT_SLEEP_MS,
    ).await
}

pub async fn get_kds_vcek(product_name: &str, chip_id: &str,
                          boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> crate::error::Result<String> {
    let cache_suffix = get_cache_suffix(product_name, chip_id);
    let cache_path = cache_dir_path(&cache_suffix, true).await;

    let cert_name = get_vcek_cert_name_prefix(boot_loader, tee, snp, microcode);

    let mut cert_file_pem = cache_path.clone();
    cert_file_pem.push(format!("{}.pem", cert_name));

    if cert_file_pem.exists().await {
        return fs::read_to_string(&cert_file_pem).await
            .map_err(|e| crate::error::io(e, Some(format!("failed to read kds vcek pem file: {}",
                                                          cert_file_pem.to_str().unwrap()))));
    }

    match fetch_kds_vcek_der(product_name, chip_id, boot_loader, tee, snp, microcode).await {
        Ok(body) => {
            // Extract pem
            let pem = pkix::pem::der_to_pem(body.as_ref(), PEM_CERTIFICATE);
            let mut output = File::create(&cert_file_pem).await
                .map_err(|e| crate::error::io(e, Some(format!("failed to create kds vcek pem file: {}",
                                                              cert_file_pem.to_str().unwrap()))))?;

            output.write_all(pem.as_bytes()).await
                .map_err(|e| crate::error::io(e, Some(format!("failed to write to kds vcek pem file: {}",
                                                              cert_file_pem.to_str().unwrap()))))?;

            Ok(pem)
        }
        Err(e) => Err(e)
    }
}

#[async_trait]
pub trait KdsCertificates {
    fn get_kds_vcek_der_url(&self) -> String;
    async fn get_kds_vcek(&self) -> crate::error::Result<String>;
}

#[async_trait]
impl KdsCertificates for AttestationReport {
    fn get_kds_vcek_der_url(&self) -> String {
        get_kds_vcek_der_url(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                             self.reported_tcb.boot_loader, self.reported_tcb.tee,
                             self.reported_tcb.snp, self.reported_tcb.microcode)
    }

    async fn get_kds_vcek(&self) -> crate::error::Result<String> {
        get_kds_vcek(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                     self.reported_tcb.boot_loader, self.reported_tcb.tee,
                     self.reported_tcb.snp, self.reported_tcb.microcode).await
    }
}

#[cfg(test)]
mod tests {
    use std::{env};
    use std::path::PathBuf;

    use crate::guest::attestation::certs::{fetch_kds_vcek_der, KdsCertificates, PRODUCT_NAME_MILAN};
    use crate::guest::attestation::report::AttestationReport;

    #[test]
    fn get_kds_vcek_url_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("resources/test/guest_report.bin");

        let report = AttestationReport::from_file(&test_file)
            .expect("failed to create AttestationReport from_file");

        assert_eq!(report.get_kds_vcek_der_url(), "https://kdsintf.amd.com/vcek/v1/Milan/9e1235cce6f3e507b66a9d3f2199a325cd0be17c6c50fd55c284ceff993dbf6c7e32fa16a76521bf6b78cc9ca482e572bde70e8c9f1bdfcb8267dea8e11ff77e?blSPL=02&teeSPL=00&snpSPL=05&ucodeSPL=115");
    }

    #[tokio::test]
    async fn fetch_kds_vcek_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("resources/test/guest_report.bin");

        let report = AttestationReport::from_file(&test_file).unwrap();

        let vcek = fetch_kds_vcek_der(
            PRODUCT_NAME_MILAN, report.chip_id_hex().as_str(),
            report.reported_tcb.boot_loader, report.reported_tcb.tee,
            report.reported_tcb.snp, report.reported_tcb.microcode).await
            .expect("failed to call fetch_kds_vcek_der");

        assert!(vcek.len() > 1000);
    }

    #[tokio::test]
    async fn get_kds_vcek_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("resources/test/guest_report.bin");

        let report = AttestationReport::from_file(&test_file).unwrap();

        let pem = report.get_kds_vcek().await
            .expect("failed to call get_kds_vcek");

        assert_ne!(pem, "");

        // Calling a second time should work (cached)
        let pem = report.get_kds_vcek().await
            .expect("failed to call get_kds_vcek");

        assert_ne!(pem, "");
    }
}