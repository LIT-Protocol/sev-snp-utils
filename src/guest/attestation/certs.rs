use async_std::fs;
use async_std::sync::RwLock;
use async_trait::async_trait;
use bytes::Bytes;
use openssl::ec::EcKey;
use openssl::pkey::Public;
use openssl::x509::X509;
use pem::parse_many;
use pkix::pem::PEM_CERTIFICATE;

use crate::{AttestationReport, error};
use crate::common::cache::cache_dir_path;
use crate::common::cert::{x509_bytes_to_ec_key, x509_validate_signature};
use crate::common::fetch::fetch_url_cached;
use crate::common::file::write_bytes_to_file;
use crate::error::Result as Result;

pub(crate) const PRODUCT_NAME_MILAN: &str = "Milan";

pub(crate) const CACHE_PREFIX: &str = "certs";

pub(crate) const FETCH_ATTEMPTS: u8 = 5;
pub(crate) const FETCH_ATTEMPT_SLEEP_MS: u64 = 7000;

const KDS_CERT_SITE: &str = "https://kdsintf.amd.com";
#[allow(dead_code)]
const KDS_DEV_CERT_SITE: &str = "https://kdsintfdev.amd.com";
#[allow(dead_code)]
const KDS_CEK: &str = "/cek/id/";
const KDS_VCEK: &str = "/vcek/v1/";               // KDS_VCEK/{product_name}/{hwid}?{tcb parameter list}
#[allow(dead_code)]
const KDS_VCEK_CERT_CHAIN: &str = "cert_chain";   // KDS_VCEK/{product_name}/cert_chain
#[allow(dead_code)]
const KDS_VCEK_CRL: &str = "crl";                 // KDS_VCEK/{product_name}/crl"

const ASK_DER_FILENAME: &str = "ask.der";
const ASK_PEM_FILENAME: &str = "ask.pem";
const ARK_DER_FILENAME: &str = "ark.der";
const ARK_PEM_FILENAME: &str = "ark.pem";

static ARK_FETCH_LOCK: RwLock<bool> = RwLock::new(true);
static VCEK_FETCH_LOCK: RwLock<bool> = RwLock::new(true);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[allow(unused)]
pub enum CertFormat {
    PEM,
    DER,
}

pub fn get_kds_vcek_cert_chain_url(product_name: &str) -> String {
    format!("{}{}{}/{}",
            KDS_CERT_SITE, KDS_VCEK, product_name, KDS_VCEK_CERT_CHAIN)
}

fn get_vcek_cache_suffix(product_name: &str) -> String {
    format!("{}/{}", CACHE_PREFIX, product_name)
}

pub async fn fetch_kds_vcek_cert_chain_pem(product_name: &str) -> Result<Bytes> {
    let save_path = format!("{}/{}.pem", get_vcek_cache_suffix(product_name),
                            KDS_VCEK_CERT_CHAIN
    );
    fetch_url_cached(
        get_kds_vcek_cert_chain_url(product_name).as_str(),
        save_path.as_str(), FETCH_ATTEMPTS, FETCH_ATTEMPT_SLEEP_MS,
    ).await
}

pub async fn get_kds_ask_and_ark_certs(product_name: &str, format: CertFormat) -> Result<(Bytes, Bytes)> {
    // Ensure all the files are written before reading.
    let _guard = ARK_FETCH_LOCK.write().await;

    let cache_suffix = get_vcek_cache_suffix(product_name);
    let cache_path = cache_dir_path(&cache_suffix, true).await;

    let mut ask_file_der = cache_path.clone();
    ask_file_der.push(ASK_DER_FILENAME);

    let mut ask_file_pem = cache_path.clone();
    ask_file_pem.push(ASK_PEM_FILENAME);

    let mut ark_file_der = cache_path.clone();
    ark_file_der.push(ARK_DER_FILENAME);

    let mut ark_file_pem = cache_path.clone();
    ark_file_pem.push(ARK_PEM_FILENAME);

    let ask_want = match format {
        CertFormat::DER => &ask_file_der,
        CertFormat::PEM => &ask_file_pem
    };
    let ark_want = match format {
        CertFormat::DER => &ark_file_der,
        CertFormat::PEM => &ark_file_pem
    };

    if ask_want.exists().await && ark_want.exists().await {
        let ask_bytes = fs::read(ask_want).await
            .map_err(|e| crate::error::io(e, Some(format!("failed to read ASK {:?} file: {}",
                                                          format, ask_want.to_str().unwrap()))))?;
        let ark_bytes = fs::read(&ark_want).await
            .map_err(|e| crate::error::io(e, Some(format!("failed to read ARK {:?} file: {}",
                                                          format, ark_want.to_str().unwrap()))))?;

        return Ok((Bytes::from(ask_bytes), Bytes::from(ark_bytes)));
    }

    match fetch_kds_vcek_cert_chain_pem(product_name).await {
        Ok(body) => {
            // Extract pems
            let pems = parse_many(body)
                .map_err(|e| crate::error::io(e, Some(format!("failed to parse ARK cert chain into PEMs"))))?;
            if pems.len() != 2 {
                return Err(crate::error::io(
                    format!("failed to parse ARK cert chain  - PEM count {} != 2", pems.len()), None,
                ));
            }

            // DER
            let ask_der_bytes = Bytes::from(pems[0].contents.clone());
            let ark_der_bytes = Bytes::from(pems[1].contents.clone());

            // Write ASK & ARK DER
            write_bytes_to_file(ask_file_der.as_path(), &ask_der_bytes).await?;
            write_bytes_to_file(ark_file_der.as_path(), &ark_der_bytes).await?;

            // PEM
            let ask_pem_bytes = Bytes::from(pkix::pem::der_to_pem(ask_der_bytes.as_ref(), PEM_CERTIFICATE));
            let ark_pem_bytes = Bytes::from(pkix::pem::der_to_pem(ark_der_bytes.as_ref(), PEM_CERTIFICATE));

            // Write ASK & ARK PEM
            write_bytes_to_file(ask_file_pem.as_path(), &ask_pem_bytes).await?;
            write_bytes_to_file(ark_file_pem.as_path(), &ark_pem_bytes).await?;

            match format {
                CertFormat::DER => Ok((ask_der_bytes, ark_der_bytes)),
                CertFormat::PEM => Ok((ask_pem_bytes, ark_pem_bytes))
            }
        }
        Err(e) => Err(e)
    }
}

pub fn validate_ark_ask_vcek_certs(ask_bytes: &Bytes, ark_bytes: &Bytes, vcek_bytes: Option<&Bytes>) -> Result<()> {
    let ark_cert = X509::from_der(ark_bytes.as_ref())
        .map_err(|e| error::cert(Some(format!("failed to parse ARK cert: {:?}", e).to_string())))?;
    let ask_cert = X509::from_der(ask_bytes.as_ref())
        .map_err(|e| error::cert(Some(format!("failed to parse ASK cert: {:?}", e).to_string())))?;

    // Verify ARK self-signed.
    x509_validate_signature(ark_cert.clone(), None, ark_cert.clone())
        .map_err(|e| error::cert(Some(format!("failed to verify ARK cert as self-signed: {:?}", e).to_string())))?;

    // Verify ASK signed by ARK.
    x509_validate_signature(ark_cert.clone(), None, ask_cert.clone())
        .map_err(|e| error::cert(Some(format!("failed to verify ASK cert signed by ARK: {:?}", e).to_string())))?;

    if let Some(vcek_bytes) = vcek_bytes {
        let vcek_cert = X509::from_der(vcek_bytes.as_ref())
            .map_err(|e| error::cert(Some(format!("failed to parse VCEK cert: {:?}", e).to_string())))?;

        // Verify VCEK signed by ASK.
        x509_validate_signature(ark_cert.clone(), Some(ask_cert.clone()), vcek_cert.clone())
            .map_err(|e| error::cert(Some(format!("failed to verify ASK cert signed by ARK: {:?}", e).to_string())))?;
    }

    Ok(())
}

pub async fn get_kds_ask_and_ark_certs_and_validate(product_name: &str) -> Result<(Bytes, Bytes)> {
    let (ask_bytes, ark_bytes) = get_kds_ask_and_ark_certs(product_name, CertFormat::DER).await?;

    validate_ark_ask_vcek_certs(&ask_bytes, &ark_bytes, None)?;

    Ok((ask_bytes, ark_bytes))
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
                                boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> Result<Bytes> {
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
                          boot_loader: u8, tee: u8, snp: u8, microcode: u8,
                          format: CertFormat) -> Result<Bytes> {
    // Ensure all the files are written before reading.
    let _guard = VCEK_FETCH_LOCK.write().await;

    let cache_suffix = get_vcek_chip_cache_suffix(product_name, chip_id);
    let cache_path = cache_dir_path(&cache_suffix, true).await;

    let cert_name = get_vcek_cert_name_prefix(boot_loader, tee, snp, microcode);

    let mut cert_file_der = cache_path.clone();
    cert_file_der.push(format!("{}.der", cert_name));

    let mut cert_file_pem = cache_path.clone();
    cert_file_pem.push(format!("{}.pem", cert_name));

    let want_file = match format {
        CertFormat::DER => &cert_file_der,
        CertFormat::PEM => &cert_file_pem
    };

    if want_file.exists().await {
        let bytes = fs::read(&want_file).await
            .map_err(|e| error::io(e, Some(format!("failed to read kds vcek {:?} file: {}",
                                                   format, want_file.to_str().unwrap()))))?;
        return Ok(Bytes::from(bytes));
    }

    match fetch_kds_vcek_der(product_name, chip_id, boot_loader, tee, snp, microcode).await {
        Ok(body) => {
            // Extract pem
            let pem_bytes = Bytes::from(pkix::pem::der_to_pem(body.as_ref(), PEM_CERTIFICATE));

            write_bytes_to_file(cert_file_pem.as_path(), &pem_bytes).await?;

            match format {
                CertFormat::DER => Ok(body),
                CertFormat::PEM => Ok(pem_bytes)
            }
        }
        Err(e) => Err(e)
    }
}

#[async_trait]
pub trait KdsCertificates {
    fn get_kds_vcek_der_url(&self) -> String;
    async fn get_kds_vcek(&self, format: CertFormat) -> Result<Bytes>;
    async fn get_kds_vcek_ec_key(&self) -> Result<EcKey<Public>>;
    async fn verify_certs(&self) -> Result<()>;
}

#[async_trait]
impl KdsCertificates for AttestationReport {
    fn get_kds_vcek_der_url(&self) -> String {
        get_kds_vcek_der_url(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                             self.platform_version.boot_loader, self.platform_version.tee,
                             self.platform_version.snp, self.platform_version.microcode)
    }

    async fn get_kds_vcek(&self, format: CertFormat) -> Result<Bytes> {
        get_kds_vcek(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                     self.platform_version.boot_loader, self.platform_version.tee,
                     self.platform_version.snp, self.platform_version.microcode, format).await
    }

    async fn get_kds_vcek_ec_key(&self) -> Result<EcKey<Public>> {
        x509_bytes_to_ec_key(
            self.get_kds_vcek(CertFormat::DER).await?
        ).map_err(|e|
            error::cert(Some(format!("failed to extract EC Key from VCEK key: {:?}", e).to_string())))
    }

    async fn verify_certs(&self) -> Result<()> {
        let (ask_bytes, ark_bytes) = get_kds_ask_and_ark_certs(PRODUCT_NAME_MILAN, CertFormat::DER).await?;
        let vcek_der = get_kds_vcek(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                                    self.platform_version.boot_loader, self.platform_version.tee,
                                    self.platform_version.snp, self.platform_version.microcode, CertFormat::DER).await?;

        validate_ark_ask_vcek_certs(&ask_bytes, &ark_bytes, Some(&vcek_der))
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;

    use crate::guest::attestation::certs::{CertFormat, fetch_kds_vcek_cert_chain_pem, fetch_kds_vcek_der, get_kds_ask_and_ark_certs, get_kds_ask_and_ark_certs_and_validate, get_kds_vcek_cert_chain_url, KdsCertificates, PRODUCT_NAME_MILAN};
    use crate::guest::attestation::report::AttestationReport;

    const TEST_REPORT_BIN: &str = "resources/test/guest_report.bin";

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
    async fn get_kds_ask_and_ark_certs_test() {
        let (ask_pem, ark_pem) = get_kds_ask_and_ark_certs(PRODUCT_NAME_MILAN, CertFormat::PEM).await
            .expect("failed to call get_kds_ask_and_ark_pem");

        assert!(ask_pem.len() > 1000);
        assert!(ark_pem.len() > 1000);

        let (ask_der, ark_der) = get_kds_ask_and_ark_certs(PRODUCT_NAME_MILAN, CertFormat::DER).await
            .expect("failed to call get_kds_ask_and_ark_pem");

        assert!(ask_der.len() > 1000);
        assert!(ark_der.len() > 1000);
    }

    #[tokio::test]
    async fn get_kds_ask_and_ark_certs_and_validate_test() {
        let (ask_pem, ark_pem) = get_kds_ask_and_ark_certs_and_validate(PRODUCT_NAME_MILAN).await
            .expect("failed to call get_kds_ask_and_ark_pem_and_validate");

        assert!(ask_pem.len() > 1000);
        assert!(ark_pem.len() > 1000);
    }

    #[test]
    fn get_kds_vcek_url_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_REPORT_BIN);

        let report = AttestationReport::from_file(&test_file)
            .expect("failed to create AttestationReport from_file");

        assert_eq!(report.get_kds_vcek_der_url(), "https://kdsintf.amd.com/vcek/v1/Milan/9e1235cce6f3e507b66a9d3f2199a325cd0be17c6c50fd55c284ceff993dbf6c7e32fa16a76521bf6b78cc9ca482e572bde70e8c9f1bdfcb8267dea8e11ff77e?blSPL=02&teeSPL=00&snpSPL=06&ucodeSPL=115");
    }

    #[tokio::test]
    async fn fetch_kds_vcek_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_REPORT_BIN);

        let report = AttestationReport::from_file(&test_file).unwrap();

        let vcek = fetch_kds_vcek_der(
            PRODUCT_NAME_MILAN, report.chip_id_hex().as_str(),
            report.platform_version.boot_loader, report.platform_version.tee,
            report.platform_version.snp, report.platform_version.microcode).await
            .expect("failed to call fetch_kds_vcek_der");

        assert!(vcek.len() > 1000);
    }

    #[tokio::test]
    async fn get_kds_vcek_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_REPORT_BIN);

        let report = AttestationReport::from_file(&test_file).unwrap();

        let pem = report.get_kds_vcek(CertFormat::PEM).await
            .expect("failed to call get_kds_vcek");

        assert_ne!(pem, "");

        // Calling a second time should work (cached)
        let der = report.get_kds_vcek(CertFormat::DER).await
            .expect("failed to call get_kds_vcek");

        assert_ne!(der, "");
    }

    #[tokio::test]
    async fn verify_certs_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_REPORT_BIN);

        let report = AttestationReport::from_file(&test_file).unwrap();

        report.verify_certs().await
            .expect("failed to call verify_certs");
    }
}