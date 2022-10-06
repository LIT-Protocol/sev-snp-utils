use std::time::Duration;
use async_std::task;
use bytes::Bytes;
use log::{debug, warn};
use crate::AttestationReport;

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

        task::sleep( Duration::from_secs( 3 ) ).await;
    }

    Ok(body)
}

pub trait KdsVcek {
    fn get_kds_vcek_url(&self) -> String;
}

impl KdsVcek for AttestationReport {
    fn get_kds_vcek_url(&self) -> String {
        get_kds_vcek_url(PRODUCT_NAME_MILAN.to_string(), self.chip_id_hex(),
                         self.reported_tcb.boot_loader, self.reported_tcb.tee,
                         self.reported_tcb.snp, self.reported_tcb.microcode)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::guest::attestation::report::AttestationReport;
    use crate::guest::attestation::vcek::{fetch_kds_vcek, KdsVcek, PRODUCT_NAME_MILAN};

    #[test]
    fn get_kds_vcek_url_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("resources/test/guest_report.bin");

        let report = AttestationReport::from_file(&test_file).unwrap();

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
            report.reported_tcb.snp, report.reported_tcb.microcode).await;

        assert_eq!(vcek.is_ok(), true);
        let vcek = vcek.unwrap();

        assert_eq!(vcek.is_some(), true);
        let vcek = vcek.unwrap();

        assert_eq!(vcek.len(), 1360);
    }
}