use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::Seek;
use std::io::{Cursor, Read};
use std::os::fd::AsRawFd;
use tracing::trace;

use crate::common::binary::read_exact_to_bin_vec;
use crate::error::{io, validation, Result};
use crate::guest::ioctl::guest_request_types::{
    snp_get_report, SNPGuestRequestGetReportIOCTL, SEV_GUEST_DEVICE,
    SNP_REPORT_MSG_RESP_RESERVED_BYTES, SNP_REPORT_RESP_HEADER_BYTES,
    SNP_REPORT_USER_DATA_MAX_BYTES,
};
use crate::{error, AttestationReport};

#[derive(Debug)]
pub struct RequestAttestationReportMsgHeader {
    pub status: u32,
    pub report_size: u32,
    pub reserved: [u8; SNP_REPORT_MSG_RESP_RESERVED_BYTES],
}

impl RequestAttestationReportMsgHeader {
    pub fn from_reader(mut rdr: impl Read + Seek) -> Result<Self> {
        let status = rdr.read_u32::<LittleEndian>().map_err(error::map_io_err)?;
        let report_size = rdr.read_u32::<LittleEndian>().map_err(error::map_io_err)?;
        let reserved = read_exact_to_bin_vec(&mut rdr, SNP_REPORT_MSG_RESP_RESERVED_BYTES)?;

        Ok(RequestAttestationReportMsgHeader {
            status,
            report_size,
            reserved: reserved
                .as_slice()
                .try_into()
                .map_err(error::map_conversion_err)?,
        })
    }
}

pub trait Requester {
    fn request_raw(data: &[u8]) -> Result<Vec<u8>>;
    fn request(data: &[u8]) -> Result<AttestationReport>;
}

impl Requester for AttestationReport {
    fn request_raw(data: &[u8]) -> Result<Vec<u8>> {
        // Validity checks.
        if data.len() > SNP_REPORT_USER_DATA_MAX_BYTES {
            return Err(validation("Too many bytes of data provided", None));
        }

        // Initialize data structures.
        let mut snp_guest_request_get_report_ioctl =
            SNPGuestRequestGetReportIOCTL::new_with_user_data(
                data.try_into().map_err(error::map_conversion_err)?,
            );

        // Open the /dev/sev-guest device.
        let fd = File::options()
            .read(true)
            .write(true)
            .open(SEV_GUEST_DEVICE)
            .map_err(|e| error::io(e, None))?;

        // Issue the guest request IOCTL.
        trace!("Issuing the guest request IOCTL");
        unsafe {
            let ret_code = snp_get_report(fd.as_raw_fd(), &mut snp_guest_request_get_report_ioctl)
                .map_err(|e| error::io(e, Some("Error sending IOCTL".into())))?;
            if ret_code == -1 {
                return Err(io(
                    format!(
                        "Firmware error: {}",
                        snp_guest_request_get_report_ioctl.fw_err
                    ),
                    None,
                ));
            }
        }
        //trace!("Received IOCTL response: {:?}", snp_guest_request_get_report_ioctl);

        // Check that the report was successfully generated.
        let mut report_msg_bytes = snp_guest_request_get_report_ioctl.resp_data.data.to_vec();
        let report_msg_header_bytes = report_msg_bytes.drain(0..SNP_REPORT_RESP_HEADER_BYTES);
        let report_msg_header_rdr = Cursor::new(report_msg_header_bytes);
        let report_msg_header =
            RequestAttestationReportMsgHeader::from_reader(report_msg_header_rdr)?;
        //trace!("Report Message Header: {:?}", report_msg_header);
        if report_msg_header.status != 0 {
            return Err(io(
                format!(
                    "Non-zero status code {:?} with the following firmware error {:?}",
                    report_msg_header.status, snp_guest_request_get_report_ioctl.fw_err
                ),
                None,
            ));
        }

        Ok(report_msg_bytes)
    }

    fn request(data: &[u8]) -> Result<AttestationReport> {
        let attestation_report_bytes = Self::request_raw(data)?;
        Ok(AttestationReport::from_reader(Cursor::new(
            attestation_report_bytes,
        ))?)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor};

    use crate::guest::attestation::get_report::SNP_REPORT_MSG_RESP_RESERVED_BYTES;

    use super::RequestAttestationReportMsgHeader;

    const TEST_MSG_RESP_BIN: &str = "resources/test/snp_report_msg_resp.bin";

    #[test]
    fn test_snp_report_msg_resp_from_reader() {
        let file_data = fs::read(TEST_MSG_RESP_BIN).unwrap();
        let snp_report_msg_resp =
            RequestAttestationReportMsgHeader::from_reader(Cursor::new(file_data)).unwrap();

        assert_eq!(snp_report_msg_resp.status, 0);
        assert_eq!(snp_report_msg_resp.report_size, 1184);
        assert_eq!(
            snp_report_msg_resp.reserved,
            [0; SNP_REPORT_MSG_RESP_RESERVED_BYTES]
        );
    }
}
