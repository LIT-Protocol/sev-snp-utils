use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;

use byteorder::{LittleEndian, ReadBytesExt};
use uuid::{Bytes, Uuid};

use crate::common::binary::read_exact_to_bin_vec;
use crate::error::{conversion, io, map_io_err, Result, validation};

const EXPECTED_METADATA_SIG: &[u8] = b"ASEV";

const FOUR_GB: u64 = 0x100000000;
const OVMF_TABLE_FOOTER_GUID: &'static str = "96b582de-1fb2-45f7-baea-a366c55a082d";
const SEV_HASH_TABLE_RV_GUID: &'static str = "7255371f-3a3b-4b04-927b-1da6efa8d454";
const SEV_ES_RESET_BLOCK_GUID: &'static str = "00f771de-1a7e-4fcb-890e-68c77e2fb44e";
const OVMF_SEV_META_DATA_GUID: &'static str = "dc886566-984a-4798-a75e-5585a7bf67cc";

/// Types of sections declared by OVMF SEV Metadata, as appears in:
/// https://github.com/tianocore/edk2/blob/edk2-stable202205/OvmfPkg/ResetVector/X64/OvmfSevMetadata.asm
#[derive(Debug, Clone)]
enum SectionType {
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

struct OvmfSevMetadataSectionDesc {
    gpa: u32,
    size: u32,
    section_type: SectionType,
}

impl OvmfSevMetadataSectionDesc {
    pub fn sizeof() -> usize {
        return 4 + 4 + 4;
    }

    fn from_reader(mut rdr: impl Read) -> Result<Self> {
        let gpa = rdr.read_u32::<LittleEndian>()
            .map_err(map_io_err)?;
        let size = rdr.read_u32::<LittleEndian>()
            .map_err(map_io_err)?;
        let section_type = rdr.read_u32::<LittleEndian>()
            .map_err(map_io_err)?;
        let section_type = SectionType::try_from(section_type as u8)?;

        Ok(
            Self { gpa, size, section_type }
        )
    }

    pub fn gpa(&self) -> u32 {
        self.gpa
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn section_type(&self) -> SectionType {
        self.section_type.clone()
    }
}

struct OvmfSevMetadataHeader {
    signature: [u8; 4],
    size: u32,
    version: u32,
    num_items: u32,
}

impl OvmfSevMetadataHeader {
    fn from_reader(mut rdr: impl Read) -> Result<Self> {
        let signature = read_exact_to_bin_vec(&mut rdr, 4)?;
        let signature: [u8; 4] = signature[..4].try_into()
            .map_err(|e| conversion(e, None))?;

        let size = rdr.read_u32::<LittleEndian>()
            .map_err(map_io_err)?;
        let version = rdr.read_u32::<LittleEndian>()
            .map_err(map_io_err)?;
        let num_items = rdr.read_u32::<LittleEndian>()
            .map_err(map_io_err)?;

        Ok(
            Self { signature, size, version, num_items }
        )
    }

    pub fn signature(&self) -> &[u8; 4] {
        &self.signature
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn version(&self) -> u32 {
        self.version
    }

    pub fn num_items(&self) -> u32 {
        self.num_items
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

pub struct OVMF {
    data: Vec<u8>,
    table: HashMap<String, Vec<u8>>,
    metadata_items: Vec<OvmfSevMetadataSectionDesc>
}

impl OVMF {
    pub fn from_path<P: AsRef<Path>>(path: P) -> Result<Self> {
        let data = fs::read(&path)
            .map_err(|e| io(e, None))?;

        let mut ovmf = Self {
            data,
            table: HashMap::new(),
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


    // Parsing

    fn parse_footer_table(&mut self) -> Result<()> {
        self.table.clear();
        let len = self.data.len();

        let footer_guid = &self.data[len-48..len-32];
        let expected_footer_guid = Uuid::try_from(OVMF_TABLE_FOOTER_GUID)
            .map_err(|e| conversion(e, None))?;
        let expected_footer_guid = expected_footer_guid.as_bytes().as_slice();
        if !footer_guid.eq(expected_footer_guid) {
            return Err(validation("OVMF table footer GUID does not match", None));
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

                let mut cursor = Cursor::new(self.data.as_slice());
                cursor.seek(SeekFrom::Start(start as u64))
                    .map_err(map_io_err)?;

                let header = OvmfSevMetadataHeader::from_reader(&mut cursor)?;
                header.verify()?;

                for i in 0..header.num_items() {
                    let offset = (i as usize) * OvmfSevMetadataSectionDesc::sizeof();

                    cursor.seek(SeekFrom::Start(offset as u64))
                        .map_err(map_io_err)?;

                    let item = OvmfSevMetadataSectionDesc::from_reader(&mut cursor)?;

                    self.metadata_items.push(item);
                }
            }
            None => {
                return Err(validation("OVMF SEV metadata: missing metadata GUID", None));
            }
        }

        Ok(())
    }
}