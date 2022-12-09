use std::io::{Read, Cursor};
use std::fs::File;
use std::io::Seek;
use std::os::fd::AsRawFd;
use byteorder::{LittleEndian, ReadBytesExt};
use log::debug;

use crate::common::binary::{read_exact_to_bin_vec, copy_to_fixed_size_byte_array};
use crate::guest::attestation::snp::{SNP_REPORT_USER_DATA_MAX_BYTES, SNPGuestRequestIOCTL, SEV_GUEST_DEVICE, snp_get_report};
use crate::{error, AttestationReport};
use crate::error::Result as Result;

use super::snp::SNP_REPORT_MSG_RESP_RESERVED_BYTES;

#[derive(Debug)]
pub struct SNPReportMsgResp {
    pub status: u32,
    pub report_size: u32,
    pub reserved: [u8; SNP_REPORT_MSG_RESP_RESERVED_BYTES],
    pub attestation_report: AttestationReport,
}

impl SNPReportMsgResp {
    pub fn from_reader(mut rdr: impl Read + Seek) -> Result<Self> {
        let status = rdr.read_u32::<LittleEndian>()
            .map_err(error::map_io_err)?;
        let report_size = rdr.read_u32::<LittleEndian>()
            .map_err(error::map_io_err)?;
        let reserved = read_exact_to_bin_vec(&mut rdr, SNP_REPORT_MSG_RESP_RESERVED_BYTES)?;
        let attestation_report = AttestationReport::from_reader(rdr)?;

        Ok(SNPReportMsgResp {
            status,
            report_size,
            reserved: copy_to_fixed_size_byte_array::<SNP_REPORT_MSG_RESP_RESERVED_BYTES>(reserved.as_slice()),
            attestation_report,
        })
    }
}

pub struct SNPAttestationReportGetter {}

impl SNPAttestationReportGetter {
    pub fn get(data: &[u8]) -> Result<AttestationReport> {
        // Validity checks.
        if data.len() > SNP_REPORT_USER_DATA_MAX_BYTES {
            return Err(error::Error::new_msg(error::Kind::InputValidation, Some("Too many bytes of data provided.".into())));
        }

        // Initialize data structures.
        let mut snp_guest_request_ioctl = SNPGuestRequestIOCTL::new_with_user_data(copy_to_fixed_size_byte_array::<SNP_REPORT_USER_DATA_MAX_BYTES>(data));
    
        // Open the /dev/sev-guest device.
        let fd = File::options().read(true).write(true).open(SEV_GUEST_DEVICE)
            .map_err(|e| error::io(e, None))?;

        // Issue the guest request IOCTL.
        debug!("Issuing the guest request IOCTL");
        unsafe {
            let ret_code = snp_get_report(fd.as_raw_fd(), &mut snp_guest_request_ioctl)
                .map_err(|e| error::io(e, Some("Error sending IOCTL".into())))?;
            if ret_code == -1 {
                return Err(error::Error::new_msg(error::Kind::Io, Some(format!("Firmware error: {}", snp_guest_request_ioctl.fw_err))));
            }
        }
        debug!("Retrieved guest report: {:?}", snp_guest_request_ioctl);
        
        // Check that the report was successfully generated.
        let snp_report_msg = SNPReportMsgResp::from_reader(Cursor::new(snp_guest_request_ioctl.resp_data.data))?;
        debug!("SNP Report Message: {:?}", snp_report_msg);
        if snp_report_msg.status != 0 {
            return Err(error::Error::new_msg(error::Kind::Io, Some(format!("Non-zero status code {:?} with the following firmware error {:?}", snp_report_msg.status, snp_guest_request_ioctl.fw_err))));
        }

        Ok(snp_report_msg.attestation_report)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor};

    use crate::guest::attestation::get_report::SNP_REPORT_MSG_RESP_RESERVED_BYTES;

    use super::SNPReportMsgResp;

    const TEST_MSG_RESP_BIN: &str = "resources/test/snp_report_msg_resp.bin";

    #[test]
    fn test_snp_report_msg_resp_from_reader() {
        let file_data = fs::read(TEST_MSG_RESP_BIN).unwrap();
        let snp_report_msg_resp = SNPReportMsgResp::from_reader(Cursor::new(file_data)).unwrap();
        
        assert_eq!(snp_report_msg_resp.status, 0);
        assert_eq!(snp_report_msg_resp.report_size, 1184);
        assert_eq!(snp_report_msg_resp.reserved, [0; SNP_REPORT_MSG_RESP_RESERVED_BYTES]);
    }
}