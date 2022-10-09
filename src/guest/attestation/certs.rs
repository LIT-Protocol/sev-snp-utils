use std::env;
use async_std::fs;
use async_std::fs::{File, OpenOptions};
use async_std::sync::{Mutex};
use async_trait::async_trait;
use bytes::Bytes;
use log::warn;
use openssl::ec::EcKey;
use openssl::pkey::Public;
use openssl::x509::X509;
use pem::parse_many;
use pkix::pem::PEM_CERTIFICATE;
use cached::{Cached, SizedCache};
use cached::once_cell::sync::Lazy;

use crate::{AttestationReport, error};
use crate::common::cache::{cache_dir_path, cache_file_path};
use crate::common::cert::{x509_to_ec_key, x509_validate_signature};
use crate::common::env::{ENV_CACHE_MEM_VCEK_LEN_DEFAULT, ENV_CACHE_MEM_VCEK_LEN_KEY};
use crate::common::fetch::fetch_url_cached;
use crate::common::file::{flock, write_bytes_to_file};
use crate::error::Result as Result;

pub(crate) const PRODUCT_NAME_MILAN: &str = "Milan";

pub(crate) const CACHE_PREFIX: &str = "certs";

pub(crate) const FETCH_ATTEMPTS: u8 = 10;
pub(crate) const FETCH_ATTEMPT_SLEEP_MS: u64 = 4000;

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

const ARK_FETCH_LOCK_FILE: &str = "ark_fetch.lock";

static ARK_CERT_CACHE: Lazy<Mutex<SizedCache<String, (X509, X509)>>> = Lazy::new(||
    Mutex::new(SizedCache::with_size(10)));
static VCEK_CERT_CACHE: Lazy<Mutex<SizedCache<String, X509>>> = Lazy::new(|| {
    let cache_size = env::var(ENV_CACHE_MEM_VCEK_LEN_KEY)
        .unwrap_or(ENV_CACHE_MEM_VCEK_LEN_DEFAULT.to_string())
        .parse::<usize>()
        .expect(format!("failed to parse env '{}' as usize", ENV_CACHE_MEM_VCEK_LEN_KEY).as_str());

    Mutex::new(SizedCache::with_size(cache_size))
});

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

pub async fn get_kds_ark_ask_certs_bytes(product_name: &str, format: CertFormat) -> Result<(Bytes, Bytes)> {
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

    let load_files = async move || -> Result<(Bytes, Bytes)> {
        let ask_bytes = fs::read(ask_want).await
            .map_err(|e| crate::error::io(e, Some(format!("failed to read ASK {:?} file: {}",
                                                          format, ask_want.to_str().unwrap()))))?;
        let ark_bytes = fs::read(&ark_want).await
            .map_err(|e| crate::error::io(e, Some(format!("failed to read ARK {:?} file: {}",
                                                          format, ark_want.to_str().unwrap()))))?;

        return Ok((Bytes::from(ark_bytes), Bytes::from(ask_bytes)));
    };

    {
        // Try read lock first and check if exists.
        let _guard = ArkFetchLockFile::read().await?;

        if ask_want.exists().await && ark_want.exists().await {
            return load_files().await;
        }
    }

    // Not found, get a write lock.
    let _guard = ArkFetchLockFile::write().await?;

    // Check one last time.
    if ask_want.exists().await && ark_want.exists().await {
        return load_files().await;
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
                CertFormat::DER => Ok((ark_der_bytes, ask_der_bytes)),
                CertFormat::PEM => Ok((ark_pem_bytes, ask_pem_bytes))
            }
        }
        Err(e) => Err(e)
    }
}

pub async fn get_kds_ark_ask_certs(product_name: &str) -> Result<(X509, X509)> {
    let cache_key = format!("{}", product_name);

    {
        // Load from cache
        let mut cache = ARK_CERT_CACHE.lock().await;

        match cache.cache_get(&cache_key) {
            Some((ark_cert, ask_cert)) => {
                return Ok((ark_cert.clone(), ask_cert.clone()));
            }
            None => {},
        }
    }

    let (ark_bytes, ask_bytes) = get_kds_ark_ask_certs_bytes(product_name,
                                                             CertFormat::DER).await?;

    let ark_cert = X509::from_der(ark_bytes.as_ref())
        .map_err(|e| error::cert(Some(format!("failed to parse ARK cert: {:?}", e).to_string())))?;
    let ask_cert = X509::from_der(ask_bytes.as_ref())
        .map_err(|e| error::cert(Some(format!("failed to parse ASK cert: {:?}", e).to_string())))?;

    // Store in cache
    let mut cache = ARK_CERT_CACHE.lock().await;

    cache.cache_set(cache_key, (ark_cert.clone(), ask_cert.clone()));

    Ok((ark_cert, ask_cert))
}

pub fn validate_ark_ask_vcek_certs(ark_cert: &X509, ask_cert: &X509, vcek_cert: Option<&X509>) -> Result<()> {
    // Verify ARK self-signed.
    x509_validate_signature(ark_cert.clone(), None, ark_cert.clone())
        .map_err(|e| error::cert(Some(format!("failed to verify ARK cert as self-signed: {:?}", e).to_string())))?;

    // Verify ASK signed by ARK.
    x509_validate_signature(ark_cert.clone(), None, ask_cert.clone())
        .map_err(|e| error::cert(Some(format!("failed to verify ASK cert signed by ARK: {:?}", e).to_string())))?;

    if let Some(vcek_cert) = vcek_cert {
        // Verify VCEK signed by ASK.
        x509_validate_signature(ark_cert.clone(), Some(ask_cert.clone()), vcek_cert.clone())
            .map_err(|e| error::cert(Some(format!("failed to verify ASK cert signed by ARK: {:?}", e).to_string())))?;
    }

    Ok(())
}

pub async fn get_kds_ark_ask_certs_and_validate(product_name: &str) -> Result<(X509, X509)> {
    let (ark_cert, ask_cert) = get_kds_ark_ask_certs(product_name).await?;

    validate_ark_ask_vcek_certs(&ark_cert, &ask_cert, None)?;

    Ok((ark_cert, ask_cert))
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

pub async fn get_kds_vcek_cert_bytes(product_name: &str, chip_id: &str,
                                     boot_loader: u8, tee: u8, snp: u8, microcode: u8,
                                     format: CertFormat) -> Result<Bytes> {
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

    let load_file = async move || -> Result<Bytes> {
        let bytes = fs::read(&want_file).await
            .map_err(|e| error::io(e, Some(format!("failed to read kds vcek {:?} file: {}",
                                                   format, want_file.to_str().unwrap()))))?;
        return Ok(Bytes::from(bytes));
    };

    {
        // Try read lock first and check if exists.
        let _guard = ArkFetchLockFile::read().await?;

        if want_file.exists().await {
            return load_file().await;
        }
    }

    // Doesn't exist, get write lock.
    let _guard = ArkFetchLockFile::write().await?;

    // Check exists one last time.
    if want_file.exists().await {
        return load_file().await;
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

pub async fn get_kds_vcek_cert(product_name: &str, chip_id: &str,
                              boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> Result<X509> {
    let cache_key = format!("{}-{}-{:0>2}{:0>2}{:0>2}{:0>2}", product_name, chip_id,
                            boot_loader, tee, snp, microcode);
    {
        // Load from cache
        let mut cache = VCEK_CERT_CACHE.lock().await;

        match cache.cache_get(&cache_key) {
            Some(cert) => return Ok(cert.clone()),
            None => {}
        }
    }

    let vcek_bytes = get_kds_vcek_cert_bytes(product_name, chip_id,
                                             boot_loader, tee, snp, microcode,
                                             CertFormat::DER).await?;
    let vcek_cert = X509::from_der(vcek_bytes.as_ref())
        .map_err(|e| error::cert(Some(format!("failed to parse VCEK cert: {:?}", e).to_string())))?;

    // Store in cache
    let mut cache = VCEK_CERT_CACHE.lock().await;

    cache.cache_set(cache_key, vcek_cert.clone());

    Ok(vcek_cert)
}

#[async_trait]
pub trait KdsCertificates {
    fn get_kds_vcek_der_url(&self) -> String;
    async fn get_kds_vcek_cert_bytes(&self, format: CertFormat) -> Result<Bytes>;
    async fn get_kds_vcek_cert(&self) -> Result<X509>;
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

    async fn get_kds_vcek_cert_bytes(&self, format: CertFormat) -> Result<Bytes> {
        get_kds_vcek_cert_bytes(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                                self.platform_version.boot_loader, self.platform_version.tee,
                                self.platform_version.snp, self.platform_version.microcode, format).await
    }

    async fn get_kds_vcek_cert(&self) -> Result<X509> {
        get_kds_vcek_cert(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                              self.platform_version.boot_loader, self.platform_version.tee,
                              self.platform_version.snp, self.platform_version.microcode).await
    }

    async fn get_kds_vcek_ec_key(&self) -> Result<EcKey<Public>> {
        x509_to_ec_key(
            self.get_kds_vcek_cert().await?
        ).map_err(|e|
            error::cert(Some(format!("failed to extract EC Key from VCEK key: {:?}", e).to_string())))
    }

    async fn verify_certs(&self) -> Result<()> {
        let (ask_cert, ark_cert) = get_kds_ark_ask_certs(PRODUCT_NAME_MILAN).await?;
        let vcek_cert = get_kds_vcek_cert(PRODUCT_NAME_MILAN, self.chip_id_hex().as_str(),
                                    self.platform_version.boot_loader, self.platform_version.tee,
                                    self.platform_version.snp, self.platform_version.microcode).await?;

        validate_ark_ask_vcek_certs(&ark_cert, &ask_cert, Some(&vcek_cert))
    }
}

// Utils

struct ArkFetchLockFile {
    file: File,
}

impl ArkFetchLockFile {
    pub async fn new(flag: libc::c_int) -> Result<Self> {
        let filename = cache_file_path(
            format!("{}/{}", CACHE_PREFIX, ARK_FETCH_LOCK_FILE).as_str(), true).await;

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(&filename).await
            .map_err(error::map_io_err)?;

        flock(&file, flag)?;

        Ok(Self { file })
    }

    pub async fn write() -> Result<Self> {
        Self::new(libc::LOCK_EX).await
    }

    pub async fn read() -> Result<Self> {
        Self::new(libc::LOCK_SH).await
    }
}

impl Drop for ArkFetchLockFile {
    fn drop(&mut self) {
        if let Err(err) = flock(&self.file, libc::LOCK_UN) {
            warn!("failed to unlock: {:?}", err);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::path::PathBuf;

    use crate::guest::attestation::certs::{CertFormat, fetch_kds_vcek_cert_chain_pem, fetch_kds_vcek_der, get_kds_ark_ask_certs, get_kds_ark_ask_certs_and_validate, get_kds_ark_ask_certs_bytes, get_kds_vcek_cert_chain_url, KdsCertificates, PRODUCT_NAME_MILAN};
    use crate::guest::attestation::report::AttestationReport;

    const TEST_REPORT_BIN: &str = "resources/test/guest_report.bin";

    const TEST_ARK_MILAN_SUBJECT_STR: &str = "[organizationalUnitName = \"Engineering\", countryName = \"US\", localityName = \"Santa Clara\", stateOrProvinceName = \"CA\", organizationName = \"Advanced Micro Devices\", commonName = \"ARK-Milan\"]";
    const TEST_SEV_MILAN_SUBJECT_STR: &str = "[organizationalUnitName = \"Engineering\", countryName = \"US\", localityName = \"Santa Clara\", stateOrProvinceName = \"CA\", organizationName = \"Advanced Micro Devices\", commonName = \"SEV-Milan\"]";
    const TEST_SEV_VCEK_SUBJECT_STR: &str = "[organizationalUnitName = \"Engineering\", countryName = \"US\", localityName = \"Santa Clara\", stateOrProvinceName = \"CA\", organizationName = \"Advanced Micro Devices\", commonName = \"SEV-VCEK\"]";

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
    async fn get_kds_ark_ask_certs_bytes_test() {
        let (ark_pem, ask_pem) = get_kds_ark_ask_certs_bytes(
            PRODUCT_NAME_MILAN, CertFormat::PEM).await
            .expect("failed to call get_kds_ark_ask_certs_bytes");

        assert!(ark_pem.len() > 1000);
        assert!(ask_pem.len() > 1000);

        let (ark_der, ask_der) = get_kds_ark_ask_certs_bytes(
            PRODUCT_NAME_MILAN, CertFormat::DER).await
            .expect("failed to call get_kds_ark_ask_certs_bytes");

        assert!(ark_der.len() > 1000);
        assert!(ask_der.len() > 1000);
    }

    #[tokio::test]
    async fn get_kds_ark_ask_certs_test() {
        let (ark_cert, ask_cert) = get_kds_ark_ask_certs(
            PRODUCT_NAME_MILAN).await
            .expect("failed to call get_kds_ark_ask_certs");

        assert_eq!(format!("{:?}", ark_cert.subject_name()), TEST_ARK_MILAN_SUBJECT_STR);
        assert_eq!(format!("{:?}", ask_cert.subject_name()), TEST_SEV_MILAN_SUBJECT_STR);
    }

    #[tokio::test]
    async fn get_kds_ark_ask_certs_and_validate_test() {
        let (ark_cert, ask_cert) = get_kds_ark_ask_certs_and_validate(PRODUCT_NAME_MILAN).await
            .expect("failed to call get_kds_ark_ask_certs_and_validate");

        assert_eq!(format!("{:?}", ark_cert.subject_name()), TEST_ARK_MILAN_SUBJECT_STR);
        assert_eq!(format!("{:?}", ask_cert.subject_name()), TEST_SEV_MILAN_SUBJECT_STR);
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
    async fn get_kds_vcek_cert_bytes_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_REPORT_BIN);

        let report = AttestationReport::from_file(&test_file).unwrap();

        let pem = report.get_kds_vcek_cert_bytes(CertFormat::PEM).await
            .expect("failed to call get_kds_vcek");

        assert_ne!(pem, "");

        // Calling a second time should work (cached)
        let der = report.get_kds_vcek_cert_bytes(CertFormat::DER).await
            .expect("failed to call get_kds_vcek");

        assert_ne!(der, "");
    }

    #[tokio::test]
    async fn get_kds_vcek_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_REPORT_BIN);

        let report = AttestationReport::from_file(&test_file).unwrap();

        let cert = report.get_kds_vcek_cert().await
            .expect("failed to call get_kds_vcek_cert");

        assert_eq!(format!("{:?}", cert.subject_name()), TEST_SEV_VCEK_SUBJECT_STR);
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