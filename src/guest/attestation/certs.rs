use async_std::fs;
use async_std::fs::File;
use async_std::io::WriteExt;
use async_trait::async_trait;
use bytes::Bytes;
use pem::parse_many;
use pkix::pem::PEM_CERTIFICATE;

use crate::AttestationReport;
use crate::common::cache::cache_dir_path;
use crate::common::fetch::fetch_url_cached;

pub(crate) const PRODUCT_NAME_MILAN: &str = "Milan";

pub(crate) const CACHE_PREFIX: &str = "certs";

pub(crate) const FETCH_ATTEMPTS: u8 = 5;
pub(crate) const FETCH_ATTEMPT_SLEEP_MS: u64 = 5000;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
#[allow(dead_code)]
const KDS_DEV_CERT_SITE: &str = "https://kdsintfdev.amd.com";
#[allow(dead_code)]
const KDS_CEK: &str = "/cek/id/";
const KDS_VCEK: &str = "/vcek/v1/";              // KDS_VCEK/{product_name}/{hwid}?{tcb parameter list}
#[allow(dead_code)]
const KDS_VCEK_CERT_CHAIN: &str = "cert_chain";  // KDS_VCEK/{product_name}/cert_chain
#[allow(dead_code)]
const KDS_VCEK_CRL: &str = "crl";                // KDS_VCEK/{product_name}/crl"

const ASK_PEM_FILENAME: &str = "ask.pem";
const ARK_PEM_FILENAME: &str = "ark.pem";


pub fn get_kds_vcek_cert_chain_url(product_name: &str) -> String {
    format!("{}{}{}/{}",
            KDS_CERT_SITE, KDS_VCEK, product_name, KDS_VCEK_CERT_CHAIN)
}

fn get_vcek_cache_suffix(product_name: &str) -> String {
    format!("{}/{}", CACHE_PREFIX, product_name)
}

pub async fn fetch_kds_vcek_cert_chain_pem(product_name: &str) -> crate::error::Result<Bytes> {
    let save_path = format!("{}/{}.pem", get_vcek_cache_suffix(product_name),
                            KDS_VCEK_CERT_CHAIN
    );
    fetch_url_cached(
        get_kds_vcek_cert_chain_url(product_name).as_str(),
        save_path.as_str(), FETCH_ATTEMPTS, FETCH_ATTEMPT_SLEEP_MS,
    ).await
}

pub async fn get_kds_ask_and_ark_pem(product_name: &str) -> crate::error::Result<(Bytes, Bytes)> {
    let cache_suffix = get_vcek_cache_suffix(product_name);
    let cache_path = cache_dir_path(&cache_suffix, true).await;

    let mut ask_file_pem = cache_path.clone();
    ask_file_pem.push(ASK_PEM_FILENAME);

    let mut ark_file_pem = cache_path.clone();
    ark_file_pem.push(ARK_PEM_FILENAME);

    if ask_file_pem.exists().await && ark_file_pem.exists().await {
        let ask_file_pem = fs::read(&ask_file_pem).await
            .map_err(|e| crate::error::io(e, Some(format!("failed to read ASK PEM file: {}",
                                                          ask_file_pem.to_str().unwrap()))))?;
        let ark_file_pem = fs::read(&ark_file_pem).await
            .map_err(|e| crate::error::io(e, Some(format!("failed to read ARK PEM file: {}",
                                                          ark_file_pem.to_str().unwrap()))))?;

        return Ok((Bytes::from(ask_file_pem), Bytes::from(ark_file_pem)));
    }

    match fetch_kds_vcek_cert_chain_pem(product_name).await {
        Ok(body) => {
            // Extract pems
            let pems = parse_many(body)
                .map_err(|e| crate::error::io(e, Some(format!("failed to parse ARK cert chain into PEMs"))))?;
            if pems.len() != 2 {
                return Err(crate::error::io(
                    format!("failed to parse ARK cert chain  - PEM count {} != 2", pems.len()), None
                ))
            }

            let ask_bytes = Bytes::from(pems[0].contents.clone());
            let ark_bytes = Bytes::from(pems[1].contents.clone());

            let ask_pem = pkix::pem::der_to_pem(ask_bytes.as_ref(), PEM_CERTIFICATE);
            let ark_pem = pkix::pem::der_to_pem(ark_bytes.as_ref(), PEM_CERTIFICATE);

            // Write ASK
            let mut ask_output = File::create(&ask_file_pem).await
                .map_err(|e| crate::error::io(e, Some(format!("failed to create ASK PEM file: {}",
                                                              ask_file_pem.to_str().unwrap()))))?;

            ask_output.write_all(ask_pem.as_bytes()).await
                .map_err(|e| crate::error::io(e, Some(format!("failed to write to ASK PEM file: {}",
                                                              ask_file_pem.to_str().unwrap()))))?;

            // Write ARK
            let mut ark_output = File::create(&ark_file_pem).await
                .map_err(|e| crate::error::io(e, Some(format!("failed to create ARK PEM file: {}",
                                                              ark_file_pem.to_str().unwrap()))))?;

            ark_output.write_all(ark_pem.as_bytes()).await
                .map_err(|e| crate::error::io(e, Some(format!("failed to write to ARK PEM file: {}",
                                                              ark_file_pem.to_str().unwrap()))))?;

            Ok((ask_bytes, ark_bytes))
        }
        Err(e) => Err(e)
    }
}

fn get_vcek_chip_cache_suffix(product_name: &str, chip_id: &str) -> String {
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
                            get_vcek_chip_cache_suffix(product_name, chip_id),
                            get_vcek_cert_name_prefix(boot_loader, tee, snp, microcode)
    );
    fetch_url_cached(
        get_kds_vcek_der_url(product_name, chip_id, boot_loader, tee, snp, microcode).as_str(),
        save_path.as_str(), FETCH_ATTEMPTS, FETCH_ATTEMPT_SLEEP_MS,
    ).await
}

pub async fn get_kds_vcek(product_name: &str, chip_id: &str,
                          boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> crate::error::Result<Bytes> {
    let cache_suffix = get_vcek_chip_cache_suffix(product_name, chip_id);
    let cache_path = cache_dir_path(&cache_suffix, true).await;

    let cert_name = get_vcek_cert_name_prefix(boot_loader, tee, snp, microcode);

    let mut cert_file_pem = cache_path.clone();
    cert_file_pem.push(format!("{}.pem", cert_name));

    if cert_file_pem.exists().await {
        let pem = fs::read(&cert_file_pem).await
            .map_err(|e| crate::error::io(e, Some(format!("failed to read kds vcek pem file: {}",
                                                          cert_file_pem.to_str().unwrap()))))?;
        return Ok(Bytes::from(pem));
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

            Ok(Bytes::from(pem))
        }
        Err(e) => Err(e)
    }
}

#[async_trait]
pub trait KdsCertificates {
    fn get_kds_vcek_der_url(&self) -> String;
    async fn get_kds_vcek(&self) -> crate::error::Result<Bytes>;
}

#[async_trait]
impl KdsCertificates for AttestationReport {
    fn get_kds_vcek_der_url(&self) -> String {
        get_kds_vcek_der_url(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                             self.reported_tcb.boot_loader, self.reported_tcb.tee,
                             self.reported_tcb.snp, self.reported_tcb.microcode)
    }

    async fn get_kds_vcek(&self) -> crate::error::Result<Bytes> {
        get_kds_vcek(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                     self.reported_tcb.boot_loader, self.reported_tcb.tee,
                     self.reported_tcb.snp, self.reported_tcb.microcode).await
    }
}

#[cfg(test)]
mod tests {
    use std::{env};
    use std::path::PathBuf;

    use crate::guest::attestation::certs::{fetch_kds_vcek_cert_chain_pem, fetch_kds_vcek_der, get_kds_ask_and_ark_pem, get_kds_vcek_cert_chain_url, KdsCertificates, PRODUCT_NAME_MILAN};
    use crate::guest::attestation::report::AttestationReport;

    #[test]
    fn get_kds_vcek_cert_chain_url_test() {
        let url = get_kds_vcek_cert_chain_url(PRODUCT_NAME_MILAN);

        assert_eq!(url, "https://kdsintf.amd.com/vcek/v1/Milan/cert_chain");
    }

    #[tokio::test]
    async fn fetch_kds_vcek_cert_chain_test() {
        let chain = fetch_kds_vcek_cert_chain_pem(PRODUCT_NAME_MILAN).await
            .expect("failed to call fetch_kds_vcek_cert_chain");

        assert!(chain.len() > 1000);
    }

    #[tokio::test]
    async fn get_kds_ask_and_ark_pem_test() {
        let (ask_pem, ark_pem) = get_kds_ask_and_ark_pem(PRODUCT_NAME_MILAN).await
            .expect("failed to call get_kds_ask_and_ark_pem");

        assert!(ask_pem.len() > 1000);
        assert!(ark_pem.len() > 1000);
    }

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