use std::{io::{Read, Seek, Cursor}, fs::File};
use std::os::fd::AsRawFd;

use byteorder::{LittleEndian, ReadBytesExt};
use log::debug;

use crate::{common::binary::read_exact_to_bin_vec, error::{self, Result}, guest::ioctl::guest_request_types::{snp_get_derived_key, SNP_DERIVED_KEY_RESP_HEADER_BYTES, SEV_GUEST_DEVICE}};

use crate::guest::ioctl::guest_request_types::{SNP_DERIVED_KEY_MSG_RESP_RESERVED_BYTES, SNPGuestRequestGetDerivedKeyIOCTL};

use super::derived_key::DerivedKey;

#[derive(Debug)]
pub struct RequestDerivedKeyMsgHeader {
    pub status: u32,
    pub reserved: [u8; SNP_DERIVED_KEY_MSG_RESP_RESERVED_BYTES],
}

impl RequestDerivedKeyMsgHeader {
    pub fn from_reader(mut rdr: impl Read + Seek) -> Result<Self> {
        let status = rdr.read_u32::<LittleEndian>()
            .map_err(error::map_io_err)?;
        let reserved = read_exact_to_bin_vec(&mut rdr, SNP_DERIVED_KEY_MSG_RESP_RESERVED_BYTES)?;

        Ok(RequestDerivedKeyMsgHeader { status, reserved: reserved.as_slice().try_into().map_err(error::map_conversion_err)? })
    }
}

pub trait DerivedKeyRequester {
    fn request(
        mix_with_tcb_version: bool,
        mix_with_svn: bool,
        mix_with_launch_measurement: bool,
        mix_with_family_id: bool,
        mix_with_image_id: bool,
        mix_with_policy: bool,
    ) -> Result<DerivedKey>;
}

impl DerivedKeyRequester for DerivedKey {
    fn request(
        mix_with_tcb_version: bool,
        mix_with_svn: bool,
        mix_with_launch_measurement: bool,
        mix_with_family_id: bool,
        mix_with_image_id: bool,
        mix_with_policy: bool,
    ) -> Result<DerivedKey> {
        // Initialize data structures.
        let mut snp_guest_request_get_derived_key_ioctl = SNPGuestRequestGetDerivedKeyIOCTL::new(
            mix_with_tcb_version,
            mix_with_svn,
            mix_with_launch_measurement,
            mix_with_family_id,
            mix_with_image_id,
            mix_with_policy,
        );

        // Open the /dev/sev-guest device.
        let fd = File::options().read(true).write(true).open(SEV_GUEST_DEVICE)
            .map_err(|e| error::io(e, None))?;

        // Issue the guest request IOCTL.
        debug!("Issuing the guest request IOCTL");
        unsafe {
            let ret_code = snp_get_derived_key(fd.as_raw_fd(), &mut snp_guest_request_get_derived_key_ioctl)
                .map_err(|e| error::io(e, Some("Error sending IOCTL".into())))?;
            if ret_code == -1 {
                return Err(error::Error::new_msg(error::Kind::Io, Some(format!("Firmware error: {}", snp_guest_request_get_derived_key_ioctl.fw_err))));
            }
        }
        debug!("Received IOCTL response: {:?}", snp_guest_request_get_derived_key_ioctl);

        // Check that the derived key was successfully retrieved.
        let mut resp_msg_bytes = snp_guest_request_get_derived_key_ioctl.resp_data.data.to_vec();
        let resp_msg_header_bytes = resp_msg_bytes.drain(0..SNP_DERIVED_KEY_RESP_HEADER_BYTES);
        let resp_msg_header_rdr = Cursor::new(resp_msg_header_bytes);
        let resp_msg_header = RequestDerivedKeyMsgHeader::from_reader(resp_msg_header_rdr)?;
        debug!("Response Message Header: {:?}", resp_msg_header);
        if resp_msg_header.status != 0 {
            return Err(error::Error::new_msg(error::Kind::Io, Some(format!("Non-zero status code {:?} with the following firmware error {:?}", resp_msg_header.status, snp_guest_request_get_derived_key_ioctl.fw_err))));
        }

        Ok(resp_msg_bytes.as_slice().try_into().map_err(error::map_conversion_err)?)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Cursor};

    use crate::guest::{derived_key::get_derived_key::RequestDerivedKeyMsgHeader, ioctl::guest_request_types::SNP_DERIVED_KEY_MSG_RESP_RESERVED_BYTES};

    const TEST_MSG_RESP_BIN: &str = "resources/test/snp_derived_key_msg_resp.bin";

    #[test]
    fn test_snp_derived_key_msg_resp_from_reader() {
        let file_data = fs::read(TEST_MSG_RESP_BIN).unwrap();
        let snp_report_msg_resp = RequestDerivedKeyMsgHeader::from_reader(Cursor::new(file_data)).unwrap();
        
        assert_eq!(snp_report_msg_resp.status, 0);
        assert_eq!(snp_report_msg_resp.reserved, [0; SNP_DERIVED_KEY_MSG_RESP_RESERVED_BYTES]);
    }
}