use std::{env, fs, io};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use async_std::task;
use async_trait::async_trait;
use bytes::Bytes;
use log::{debug, warn};
use pkix::pem::PEM_CERTIFICATE;

use crate::AttestationReport;

pub const ENV_KDS_VCEK_PATH_KEY: &str = "KDS_VCEK_PATH";
pub const ENV_KDS_VCEK_PATH_DEFAULT: &str = "/var/cache/amd/vcek";

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
const KDS_VCEK_CRL: &str = "crl";          // KDS_VCEK/{product_name}/crl"

pub(crate) const PRODUCT_NAME_MILAN: &str = "Milan";

pub fn get_kds_vcek_url(product_name: String, chip_id: String,
                        boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> String {
    format!("{}{}{}/{}?blSPL={:0>2}&teeSPL={:0>2}&snpSPL={:0>2}&ucodeSPL={:0>2}",
            KDS_CERT_SITE, KDS_VCEK, product_name, chip_id, boot_loader, tee, snp, microcode)
}

pub async fn fetch_kds_vcek(product_name: String, chip_id: String,
                            boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> ::reqwest::Result<Option<Bytes>> {
    let url = get_kds_vcek_url(product_name, chip_id, boot_loader, tee, snp, microcode);

    // KDS will only allow requests every 10 seconds.
    let mut body: Option<Bytes> = None;
    for _ in 0..4 {
        match reqwest::get(&url).await {
            Ok(response) => {
                if response.status().is_success() {
                    body = Some(response.bytes().await?);
                    break;
                } else {
                    debug!("failed to fetch VCEK from KDS, status: {}", response.status());
                }
            }
            Err(err) => {
                warn!("failed to fetch VCEK from KDS, err: {:?}", err);
            }
        }

        task::sleep(Duration::from_secs(3)).await;
    }

    Ok(body)
}

pub async fn get_kds_vcek(product_name: String, chip_id: String,
                          boot_loader: u8, tee: u8, snp: u8, microcode: u8) -> Result<String, io::Error> {
    let cert_path = PathBuf::from(format!("{}/{}/{}",
                                          env::var(ENV_KDS_VCEK_PATH_KEY)
                                              .unwrap_or(ENV_KDS_VCEK_PATH_DEFAULT.to_string()),
                                          product_name, chip_id));
    if !cert_path.exists() {
        fs::create_dir_all(&cert_path)
            .expect(format!("failed to create dir: {} \
            (hint: you can change the path by setting {})",
                            cert_path.to_str().unwrap(), ENV_KDS_VCEK_PATH_KEY).as_str());
    }

    let cert_name = format!("{:0>2}{:0>2}{:0>2}{:0>2}",
                            boot_loader, tee, snp, microcode);

    let mut cert_file_pem = cert_path.clone();
    cert_file_pem.push(format!("{}.pem", cert_name));

    if cert_file_pem.exists() {
        return fs::read_to_string(cert_file_pem);
    }

    match fetch_kds_vcek(product_name, chip_id, boot_loader, tee, snp, microcode).await
        .map_err(|e|
            io::Error::new(io::ErrorKind::Other, e))? {
        Some(body) => {
            // Save der
            let mut cert_file_der = cert_path.clone();
            cert_file_der.push(format!("{}.der", cert_name));

            let mut output = File::create(&cert_file_der)?;

            output.write_all(body.as_ref())?;

            // Save pem
            let pem = pkix::pem::der_to_pem(body.as_ref(), PEM_CERTIFICATE);
            let mut output = File::create(&cert_file_pem)?;

            write!(output, "{}", pem)?;

            Ok(pem)
        }
        None => Err(
            io::Error::new(io::ErrorKind::Other,
                           "no vcek returned from ARK (retries exhausted?)")
        )
    }
}

#[async_trait]
pub trait KdsVcek {
    fn get_kds_vcek_url(&self) -> String;
    async fn get_kds_vcek(&self) -> Result<String, io::Error>;
}

#[async_trait]
impl KdsVcek for AttestationReport {
    fn get_kds_vcek_url(&self) -> String {
        get_kds_vcek_url(PRODUCT_NAME_MILAN.to_string(), self.chip_id_hex(),
                         self.reported_tcb.boot_loader, self.reported_tcb.tee,
                         self.reported_tcb.snp, self.reported_tcb.microcode)
    }

    async fn get_kds_vcek(&self) -> Result<String, io::Error> {
        get_kds_vcek(PRODUCT_NAME_MILAN.to_string(), self.chip_id_hex(),
                     self.reported_tcb.boot_loader, self.reported_tcb.tee,
                     self.reported_tcb.snp, self.reported_tcb.microcode).await
    }
}

#[cfg(test)]
mod tests {
    use std::{env, fs};
    use std::path::PathBuf;

    use crate::guest::attestation::report::AttestationReport;
    use crate::guest::attestation::vcek::{ENV_KDS_VCEK_PATH_KEY, fetch_kds_vcek, KdsVcek, PRODUCT_NAME_MILAN};

    #[test]
    fn get_kds_vcek_url_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("resources/test/guest_report.bin");

        let report = AttestationReport::from_file(&test_file)
            .expect("failed to create AttestationReport from_file");

        assert_eq!(report.get_kds_vcek_url(), "https://kdsintf.amd.com/vcek/v1/Milan/9e1235cce6f3e507b66a9d3f2199a325cd0be17c6c50fd55c284ceff993dbf6c7e32fa16a76521bf6b78cc9ca482e572bde70e8c9f1bdfcb8267dea8e11ff77e?blSPL=02&teeSPL=00&snpSPL=05&ucodeSPL=115");
    }

    #[tokio::test]
    async fn fetch_kds_vcek_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("resources/test/guest_report.bin");

        let report = AttestationReport::from_file(&test_file).unwrap();

        let vcek = fetch_kds_vcek(
            PRODUCT_NAME_MILAN.to_string(), report.chip_id_hex(),
            report.reported_tcb.boot_loader, report.reported_tcb.tee,
            report.reported_tcb.snp, report.reported_tcb.microcode).await
            .expect("failed to call fetch_kds_vcek");

        assert_eq!(vcek.is_some(), true);
        let vcek = vcek.unwrap();

        assert!(vcek.len() > 1000);
    }

    #[tokio::test]
    async fn get_kds_vcek_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("resources/test/guest_report.bin");

        let out_path = PathBuf::from("/tmp/sev-snp-utils-test");
        if out_path.exists() {
            fs::remove_dir_all(&out_path).unwrap();
        }
        env::set_var(ENV_KDS_VCEK_PATH_KEY, out_path.to_str().unwrap());

        let report = AttestationReport::from_file(&test_file).unwrap();

        let pem = report.get_kds_vcek().await
            .expect("failed to call get_kds_vcek");

        // Clean up.
        if out_path.exists() {
            fs::remove_dir_all(&out_path).unwrap();
        }

        assert_ne!(pem, "");
    }
}