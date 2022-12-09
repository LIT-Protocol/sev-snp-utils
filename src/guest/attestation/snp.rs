use nix::ioctl_readwrite;

pub const SEV_GUEST_DEVICE: &str = "/dev/sev-guest";

// ref: https://github.com/torvalds/linux/blob/d6ecaa0024485effd065124fe774de2e22095f2d/include/uapi/linux/sev-guest.h
const SNP_GET_REPORT_IOC_SEQUENCE_NUMBER: u8 = 0;
const SNP_GUEST_REQ_IOC_TYPE: u8 = b'S';

pub const SNP_REPORT_USER_DATA_MAX_BYTES: usize = 64;
pub const SNP_REPORT_MSG_RESP_RESERVED_BYTES: usize = 0x20 - 0x8;
pub const SNP_REPORT_REQ_RESERVED_BYTES: usize = 28;
pub const SNP_REPORT_RESP_DATA_BYTES: usize = 4000;

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
pub struct SNPGuestRequestIOCTL {
    pub msg_version: u8,
    pub req_data: Box<SNPReportReq>,
    pub resp_data: Box<SNPReportResp>,
    pub fw_err: u64,
}

impl SNPGuestRequestIOCTL {
    pub fn new_with_user_data(user_data: [u8; SNP_REPORT_USER_DATA_MAX_BYTES]) -> Self {
        SNPGuestRequestIOCTL {
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

ioctl_readwrite!(snp_get_report, SNP_GUEST_REQ_IOC_TYPE, SNP_GET_REPORT_IOC_SEQUENCE_NUMBER, SNPGuestRequestIOCTL);
