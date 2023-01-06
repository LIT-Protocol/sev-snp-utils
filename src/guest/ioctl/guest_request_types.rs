use nix::ioctl_readwrite;

pub const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

// ref: https://github.com/torvalds/linux/blob/d6ecaa0024485effd065124fe774de2e22095f2d/include/uapi/linux/sev-guest.h
const SNP_GET_REPORT_IOC_SEQUENCE_NUMBER: u8 = 0;
const SNP_GET_DERIVED_KEY_IOC_SEQUENCE_NUMBER: u8 = 1;
const SNP_GUEST_REQ_IOC_TYPE: u8 = b'S';

pub const SNP_REPORT_USER_DATA_MAX_BYTES: usize = 64;
pub const SNP_REPORT_MSG_RESP_RESERVED_BYTES: usize = 0x20 - 0x8;
pub const SNP_REPORT_REQ_RESERVED_BYTES: usize = 28;
pub const SNP_REPORT_RESP_DATA_BYTES: usize = 4000;
pub const SNP_REPORT_RESP_HEADER_BYTES: usize = 0x20;

pub const SNP_DERIVED_KEY_RESP_DATA_BYTES: usize = 64;
pub const SNP_DERIVED_KEY_MSG_RESP_RESERVED_BYTES: usize = 0x20 - 0x4;
pub const SNP_DERIVED_KEY_RESP_HEADER_BYTES: usize = 0x20;

#[repr(C)]
#[derive(Debug)]
pub struct SNPReportReq {
    pub user_data: [u8; SNP_REPORT_USER_DATA_MAX_BYTES],
    pub vmpl: u32,
    pub rsvd: [u8; SNP_REPORT_REQ_RESERVED_BYTES],
}

#[repr(C)]
#[derive(Debug)]
pub struct SNPReportResp {
    pub data: [u8; SNP_REPORT_RESP_DATA_BYTES],
}

#[repr(C)]
#[derive(Debug)]
pub struct SNPGuestRequestGetReportIOCTL {
    pub msg_version: u8,
    pub req_data: Box<SNPReportReq>,
    pub resp_data: Box<SNPReportResp>,
    pub fw_err: u64,
}

impl SNPGuestRequestGetReportIOCTL {
    pub fn new_with_user_data(user_data: [u8; SNP_REPORT_USER_DATA_MAX_BYTES]) -> Self {
        SNPGuestRequestGetReportIOCTL {
            msg_version: 1,
            req_data: Box::new(SNPReportReq {
                user_data,
                vmpl: 0,
                rsvd: [0; SNP_REPORT_REQ_RESERVED_BYTES],
            }),
            resp_data: Box::new(SNPReportResp {
                data: [0; SNP_REPORT_RESP_DATA_BYTES],
            }),
            fw_err: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct SNPDerivedKeyReq {
    pub root_key_select: u32,
    pub rsvd: u32,
    pub guest_field_select: u64,
    pub vmpl: u32,
    pub guest_svn: u32,
    pub tcb_version: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct SNPDerivedKeyResp {
    pub data: [u8; SNP_DERIVED_KEY_RESP_DATA_BYTES],
}

#[repr(C)]
#[derive(Debug)]
pub struct SNPGuestRequestGetDerivedKeyIOCTL {
    pub msg_version: u8,
    pub req_data: Box<SNPDerivedKeyReq>,
    pub resp_data: Box<SNPDerivedKeyResp>,
    pub fw_err: u64,
}

impl SNPGuestRequestGetDerivedKeyIOCTL {
    fn get_guest_field_select_bitmask(
        mix_with_tcb_version: bool,
        mix_with_svn: bool,
        mix_with_launch_measurement: bool,
        mix_with_family_id: bool,
        mix_with_image_id: bool,
        mix_with_policy: bool,
    ) -> u64 {
        let mut bitmask = 0;

        if mix_with_tcb_version {
            bitmask += 1 << 5;
        }

        if mix_with_svn {
            bitmask += 1 << 4;
        }

        if mix_with_launch_measurement {
            bitmask += 1 << 3;
        }

        if mix_with_family_id {
            bitmask += 1 << 2;
        }

        if mix_with_image_id {
            bitmask += 1 << 1;
        }

        if mix_with_policy {
            bitmask += 1 << 0;
        }

        bitmask
    }

    pub fn new(
        mix_with_tcb_version: bool,
        mix_with_svn: bool,
        mix_with_launch_measurement: bool,
        mix_with_family_id: bool,
        mix_with_image_id: bool,
        mix_with_policy: bool,
    ) -> Self {
        SNPGuestRequestGetDerivedKeyIOCTL {
            msg_version: 1,
            req_data: Box::new(SNPDerivedKeyReq {
                root_key_select: 0,
                rsvd: 0,
                guest_field_select: Self::get_guest_field_select_bitmask(
                    mix_with_tcb_version,
                    mix_with_svn,
                    mix_with_launch_measurement,
                    mix_with_family_id,
                    mix_with_image_id,
                    mix_with_policy,
                ),
                vmpl: 0,
                guest_svn: 0,
                tcb_version: 0
            }),
            resp_data: Box::new(SNPDerivedKeyResp {
                data: [0; SNP_DERIVED_KEY_RESP_DATA_BYTES],
            }),
            fw_err: 0,
        }
    }
}

ioctl_readwrite!(snp_get_report, SNP_GUEST_REQ_IOC_TYPE, SNP_GET_REPORT_IOC_SEQUENCE_NUMBER, SNPGuestRequestGetReportIOCTL);
ioctl_readwrite!(snp_get_derived_key, SNP_GUEST_REQ_IOC_TYPE, SNP_GET_DERIVED_KEY_IOC_SEQUENCE_NUMBER, SNPGuestRequestGetDerivedKeyIOCTL);