use bytemuck::Zeroable;
use crate::common::binary::fmt_slice_vec_to_hex;
use crate::common::hash::sha384;
use crate::error::{conversion, Result, validation};
use crate::guest::identity::types::{ID_BLK_DIGEST_BYTES, LaunchDigest, LD_ZEROED};

pub const BLOCK_SIZE: usize = 4096;

/// VMSA page is recorded in the RMP table with GPA (u64)(-1).
/// However, the address is page-aligned, and also all the bits above
/// 51 are cleared.
const VMSA_GPA: u64 = 0xFFFFFFFFF000;

pub struct GCTX {
    ld: LaunchDigest
}

impl GCTX {
    pub fn new() -> Self {
        Self { ld: LaunchDigest::zeroed() }
    }

    pub fn ld(&self) -> &LaunchDigest {
        &self.ld
    }

    pub fn take_ld(self) -> LaunchDigest {
        self.ld
    }

    pub fn hex_ld(&self) -> String {
        fmt_slice_vec_to_hex(self.ld().0.as_slice())
    }

    fn update(&mut self, page_type: u8, gpa: u64, contents: &[u8]) -> Result<()> {
        if contents.len() != ID_BLK_DIGEST_BYTES {
            return Err(validation(format!("contents must be of len ID_BLK_DIGEST_BYTES ({} vs {})",
                                          contents.len(), ID_BLK_DIGEST_BYTES), None));
        }

        let page_info_len: u16 = 0x70;
        let is_imi: u8 = 0;
        let vmpl3_perms: u8 = 0;
        let vmpl2_perms: u8 = 0;
        let vmpl1_perms: u8 = 0;

        // SNP spec 8.17.2 Table 67 Layout of the PAGE_INFO structure
        let mut page_info = self.ld.to_vec();
        page_info.extend_from_slice(contents);

        page_info.extend_from_slice(&page_info_len.to_le_bytes());
        page_info.extend_from_slice(&page_type.to_le_bytes());
        page_info.extend_from_slice(&is_imi.to_le_bytes());

        page_info.extend_from_slice(&vmpl3_perms.to_le_bytes());
        page_info.extend_from_slice(&vmpl2_perms.to_le_bytes());
        page_info.extend_from_slice(&vmpl1_perms.to_le_bytes());
        page_info.extend_from_slice(&(0 as u8).to_le_bytes());

        page_info.extend_from_slice(&gpa.to_le_bytes());

        if page_info.len() != (page_info_len as usize) {
            return Err(validation(format!("page_info was not the correct length ({} vs {})",
                                          page_info.len(), page_info_len), None));
        }

        let ld = sha384(&page_info).to_vec();
        if ld.len() != ID_BLK_DIGEST_BYTES {
            return Err(validation(format!("new ld is not of len ID_BLK_DIGEST_BYTES ({} vs {})",
                                          ld.len(), ID_BLK_DIGEST_BYTES), None));
        }

        self.ld = LaunchDigest::try_from(&ld[..])
            .map_err(|e| conversion(e, None))?;

        Ok(())
    }

    pub fn update_normal_pages(&mut self, start_gpa: u64, data: &[u8]) -> Result<()> {
        if (data.len() % BLOCK_SIZE) != 0 {
            return Err(validation(format!("provided data does not conform to a {} block size",
                                          BLOCK_SIZE), None));
        }

        let mut offset = 0;
        while offset < data.len() {
            let page_data = &data[offset..offset+BLOCK_SIZE];
            self.update(0x01, start_gpa + (offset as u64),
                        sha384(&page_data).as_slice())?;
            offset += BLOCK_SIZE;
        }

        Ok(())
    }

    pub fn update_vmsa_page(&mut self, data: &[u8]) -> Result<()> {
        if data.len() != BLOCK_SIZE {
            return Err(validation(format!("provided data does not conform to a {} block size",
                                          BLOCK_SIZE), None));
        }

        self.update(0x02, VMSA_GPA,
                    sha384(&data).as_slice())?;

        Ok(())
    }

    pub fn update_zero_pages(&mut self, gpa: u64, length_bytes: usize) -> Result<()> {
        if (length_bytes % BLOCK_SIZE) != 0 {
            return Err(validation(format!("provided length_bytes does not conform to a {} block size",
                                          BLOCK_SIZE), None));
        }

        let mut offset = 0;
        while offset < length_bytes {
            self.update(0x03, gpa + (offset as u64), &LD_ZEROED.0)?;
            offset += BLOCK_SIZE;
        }

        Ok(())
    }

    pub fn update_unmeasured_page(&mut self, gpa: u64) -> Result<()> {
        self.update(0x04,  gpa, &LD_ZEROED.0)?;

        Ok(())
    }

    pub fn update_secrets_page(&mut self, gpa: u64) -> Result<()> {
        self.update(0x05,  gpa, &LD_ZEROED.0)?;

        Ok(())
    }

    pub fn update_cpuid_page(&mut self, gpa: u64) -> Result<()> {
        self.update(0x06,  gpa, &LD_ZEROED.0)?;

        Ok(())
    }
}