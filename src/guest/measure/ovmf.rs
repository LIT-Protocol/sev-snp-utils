use std::collections::HashMap;
use std::fs;
use std::path::Path;
use bytemuck::{Pod, try_from_bytes, Zeroable};

use libc::{c_uchar, c_uint};
use uuid::{Bytes, Uuid};

use crate::common::binary::{fmt_slice_vec_to_hex};
use crate::common::guid::guid_le_to_slice;
use crate::error::{conversion, io, Result, validation};

const EXPECTED_METADATA_SIG: &[u8] = b"ASEV";

const FOUR_GB: u64 = 0x100000000;
const OVMF_TABLE_FOOTER_GUID: &'static str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const SEV_HASH_TABLE_RV_GUID: &'static str = "7255371f-3a3b-4b04-927b-1da6efa8d454";
const SEV_ES_RESET_BLOCK_GUID: &'static str = "00f771de-1a7e-4fcb-890e-68c77e2fb44e";
const OVMF_SEV_META_DATA_GUID: &'static str = "dc886566-984a-4798-a75e-5585a7bf67cc";

/// Types of sections declared by OVMF SEV Metadata, as appears in:
/// https://github.com/tianocore/edk2/blob/edk2-stable202205/OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm
#[derive(Debug, Clone, PartialEq)]
pub enum SectionType {
    SnpSecMem = 1,
    SnpSecrets = 2,
    CPUID = 3,
}

impl TryFrom<u8> for SectionType {
    type Error = crate::error::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(SectionType::SnpSecMem),
            2 => Ok(SectionType::SnpSecrets),
            3 => Ok(SectionType::CPUID),
            _ => {
                return Err(conversion(format!("value: '{}' cannot map to SectionType", value), None));
            }
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OvmfSevMetadataSectionDesc {
    gpa: c_uint,
    size: c_uint,
    section_type_id: c_uint,
}

impl OvmfSevMetadataSectionDesc {
    pub fn try_from_bytes(value: &[u8], offset: usize) -> Result<&Self> {
        let value = &value[offset..offset +
            std::mem::size_of::<OvmfSevMetadataSectionDesc>()];

        try_from_bytes(value)
            .map_err(|e| conversion(e.to_string(), None))
    }

    pub fn gpa(&self) -> u32 {
        self.gpa as u32
    }

    pub fn size(&self) -> u32 {
        self.size as u32
    }

    pub fn section_type_id(&self) -> u32 {
        self.section_type_id as u32
    }

    pub fn section_type(&self) -> Result<SectionType> {
        SectionType::try_from(self.section_type_id as u8)
    }
}

unsafe impl Zeroable for OvmfSevMetadataSectionDesc {

}

unsafe impl Pod for OvmfSevMetadataSectionDesc {

}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct OvmfSevMetadataHeader {
    signature: [c_uchar; 4],
    size: c_uint,
    version: c_uint,
    num_items: c_uint,
}

impl OvmfSevMetadataHeader {
    pub fn try_from_bytes(value: &[u8], offset: usize) -> Result<&Self> {
        let value = &value[offset..offset +
            std::mem::size_of::<OvmfSevMetadataHeader>()];

        try_from_bytes(value)
            .map_err(|e| conversion(e.to_string(), None))
    }

    pub fn signature(&self) -> &[u8; 4] {
        &self.signature
    }

    pub fn size(&self) -> u32 {
        self.size as u32
    }

    pub fn version(&self) -> u32 {
        self.version as u32
    }

    pub fn num_items(&self) -> u32 {
        self.num_items as u32
    }

    pub fn verify(&self) -> Result<()> {
        if !self.signature.eq(EXPECTED_METADATA_SIG) {
            return match String::from_utf8(self.signature.to_vec()) {
                Ok(sig) => {
                    Err(validation(format!("Wrong SEV metadata signature: {}", sig),
                                   None))
                }
                Err(_e) => {
                    Err(validation(format!("Wrong SEV metadata signature: {:?}", self.signature),
                                   None))
                }
            };
        }
        if self.version != 1 {
            return Err(validation(format!("Wrong SEV metadata version: {:?}", self.version),
                           None));
        }

        Ok(())
    }
}

unsafe impl Zeroable for OvmfSevMetadataHeader {

}

unsafe impl Pod for OvmfSevMetadataHeader {

}

pub struct OVMF {
    data: Vec<u8>,
    table: HashMap<String, Vec<u8>>,
    metadata_header: Option<OvmfSevMetadataHeader>,
    metadata_items: Vec<OvmfSevMetadataSectionDesc>
}

impl OVMF {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = fs::read(&path)
            .map_err(|e| io(e, None))?;

        let mut ovmf = Self {
            data,
            table: HashMap::new(),
            metadata_header: None,
            metadata_items: Vec::new()
        };

        ovmf.parse_footer_table()?;
        ovmf.parse_sev_metadata()?;

        Ok(ovmf)
    }

    // Accessors

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn gpa(&self) -> u64 {
        FOUR_GB - (self.data.len() as u64)
    }

    pub fn table_item(&self, guid: &str) -> Option<&Vec<u8>> {
        self.table.get(guid)
    }

    pub fn metadata_items(&self) -> &Vec<OvmfSevMetadataSectionDesc> {
        &self.metadata_items
    }

    pub fn sev_hashes_table_gpa(&self) -> Result<i32> {
        match self.table_item(SEV_HASH_TABLE_RV_GUID) {
            Some(entry) => {
                let val: [u8; 4] = entry[..4]
                    .try_into()
                    .map_err(|e| conversion(e, None))?;
                let val: i32 = i32::from_le_bytes(val);

                Ok(val)
            }
            None => {
                return Err(validation("OVMF SEV metadata: missing table guid 'SEV_HASH_TABLE_RV_GUID'", None));
            }
        }
    }

    pub fn sev_es_reset_eip(&self) -> Result<u64> {
        match self.table_item(SEV_ES_RESET_BLOCK_GUID) {
            Some(entry) => {
                let val: [u8; 4] = entry[..4]
                    .try_into()
                    .map_err(|e| conversion(e, None))?;
                let val: i32 = i32::from_le_bytes(val);
                if val < 0 {
                    return Err(validation("sev_es_reset_eip < 0", None));
                }

                Ok(val as u64)
            }
            None => {
                return Err(validation("OVMF SEV metadata: missing table guid 'SEV_ES_RESET_BLOCK_GUID'", None));
            }
        }
    }

    // Parsing

    fn parse_footer_table(&mut self) -> Result<()> {
        self.table.clear();
        let len = self.data.len();

        let footer_guid = &self.data[len-48..len-32];
        let expected_footer_guid = guid_le_to_slice(OVMF_TABLE_FOOTER_GUID)?;
        if !footer_guid.eq(&expected_footer_guid) {
            return Err(validation(format!("OVMF table footer GUID does not match ({} vs {})",
                                          fmt_slice_vec_to_hex(&expected_footer_guid),
                                          fmt_slice_vec_to_hex(footer_guid)), None));
        }

        let full_table_size: [u8; 2] = self.data[len-50..len-48].try_into()
            .map_err(|e| conversion(e, None))?;
        let full_table_size: i16 = i16::from_le_bytes(full_table_size);
        let table_size = full_table_size - 16 - 2;
        if table_size < 0 {
            return Err(validation("OVMF table footer: table size < 0", None));
        }
        let table_size: usize = table_size as usize;

        let mut table_bytes = &self.data[len-50-table_size..len-50];
        while table_bytes.len() >= (16 + 2) {
            let table_bytes_len = table_bytes.len();
            let entry_guid = &table_bytes[table_bytes_len-16..];
            let entry_guid_bytes: Bytes = entry_guid
                .try_into()
                .map_err(|e| conversion(e, None))?;
            let entry_guid_str = Uuid::from_bytes_le(entry_guid_bytes).to_string();

            let entry_size: [u8; 2] = table_bytes[table_bytes_len-18..table_bytes_len-16]
                .try_into()
                .map_err(|e| conversion(e, None))?;
            let entry_size: i16 = i16::from_le_bytes(entry_size);
            if entry_size < (16 + 2) {
                return Err(validation("OVMF table footer: invalid entry size", None));
            }
            let entry_size: usize = entry_size as usize;

            let entry_data = &table_bytes[table_bytes_len-entry_size..table_bytes_len-18];

            self.table.insert(entry_guid_str, entry_data.to_vec());

            table_bytes = &table_bytes[..table_bytes_len-entry_size];
        }

        Ok(())
    }

    fn parse_sev_metadata(&mut self) -> Result<()> {
        match self.table.get(OVMF_SEV_META_DATA_GUID) {
            Some(entry) => {
                let offset_from_end: [u8; 4] = entry[..4]
                    .try_into()
                    .map_err(|e| conversion(e, None))?;
                let offset_from_end: i32 = i32::from_le_bytes(offset_from_end);
                let start = self.data.len() - (offset_from_end as usize);

                let header =
                    OvmfSevMetadataHeader::try_from_bytes(self.data.as_slice(), start)?;
                header.verify()?;

                let items = &self.data[start+std::mem::size_of::<OvmfSevMetadataHeader>()..start+(header.size as usize)];

                for i in 0..header.num_items() {
                    let offset = (i as usize) * std::mem::size_of::<OvmfSevMetadataSectionDesc>();

                    let item =
                        OvmfSevMetadataSectionDesc::try_from_bytes(items, offset)?;

                    self.metadata_items.push(item.to_owned());
                }

                self.metadata_header = Some(header.to_owned());
            }
            None => {
                return Err(validation("OVMF SEV metadata: missing metadata GUID", None));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use crate::common::binary::fmt_slice_vec_to_hex;
    use crate::guest::measure::ovmf::{OVMF, SectionType};

    #[test]
    fn ovmf_file_test() {
        const TEST_OVMF_CODE_FILE: &str = "resources/test/measure/OVMF_CODE.fd";

        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push(TEST_OVMF_CODE_FILE);

        let ovmf = OVMF::from_path(&test_file)
            .expect("failed to load OVMF file");

        let metadata_header = ovmf.metadata_header.unwrap();
        metadata_header.verify().unwrap();

        assert_eq!(metadata_header.size, 76);
        assert_eq!(metadata_header.num_items, 5);

        // metadata_items
        assert_eq!(ovmf.metadata_items().len(), 5);

        for (idx, exp_gpa, exp_size, exp_section_type_id, exp_section_type) in vec![
            (0, 8388608, 36864, 1, SectionType::SnpSecMem),
            (1, 8429568, 12288, 1, SectionType::SnpSecMem),
            (2, 8441856, 4096, 2, SectionType::SnpSecrets),
            (3, 8445952, 4096, 3, SectionType::CPUID),
            (4, 8454144, 65536, 1, SectionType::SnpSecMem),
        ] {
            println!("Running metadata_items test idx: {}", idx);

            match ovmf.metadata_items().get(idx) {
                Some(item) => {
                    assert_eq!(exp_gpa, item.gpa());
                    assert_eq!(exp_size, item.size());
                    assert_eq!(exp_section_type_id, item.section_type_id());
                    assert_eq!(exp_section_type, item.section_type().unwrap());
                }
                None => {
                    panic!("missing metadata_items idx: {}", idx);
                }
            }
        }

        // table
        assert_eq!(ovmf.table.len(), 5);

        for (guid, data) in vec![
            ("00f771de-1a7e-4fcb-890e-68c77e2fb44e", "04b08000"),
            ("4c2eb361-7d9b-4cc3-8081-127c90d3d294", "00f08000000c0000"),
            ("7255371f-3a3b-4b04-927b-1da6efa8d454", "00fc800000040000"),
            ("dc886566-984a-4798-a75e-5585a7bf67cc", "2c050000"),
            ("e47a6535-984a-4798-865e-4685a7bf8ec2", "40080000")
        ] {
            println!("Running table_item test guid: {}", guid);

            match ovmf.table_item(guid) {
                Some(entry) => {
                    assert_eq!(data, fmt_slice_vec_to_hex(entry));
                }
                None => {
                    panic!("missing table guid: {}", guid);
                }
            }
        }

        // sev_hashes_table_gpa
        assert_eq!(ovmf.sev_hashes_table_gpa().unwrap(), 8453120);

        // sev_es_reset_eip
        assert_eq!(ovmf.sev_es_reset_eip().unwrap(), 8433668);
    }
}