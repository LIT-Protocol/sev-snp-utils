use std::path::Path;
use std::str::FromStr;
use bytemuck::{bytes_of, Pod, Zeroable};
use libc::{c_uchar, c_ushort};
use sha2::digest::consts::U32;
use sha2::digest::typenum::Unsigned;
use crate::common::guid::guid_le_to_slice;
use crate::common::hash::{sha256, sha256_file};

use crate::error::{conversion, Result};

const SEV_HASH_TABLE_HEADER_GUID: &'static str = "9438d606-4f22-4cc9-b479-a793d411fd21";
const SEV_KERNEL_ENTRY_GUID: &'static str = "4de79437-abd2-427f-b835-d5b172d2045b";
const SEV_INITRD_ENTRY_GUID: &'static str = "44baf731-3a2f-4bd7-9af1-41e29169781d";
const SEV_CMDLINE_ENTRY_GUID: &'static str = "97d02dd8-bd20-4c94-aa78-e7714d36ab2a";

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct Sha256Hash([c_uchar; U32::USIZE]);

#[repr(transparent)]
#[derive(Debug, Clone, Copy)]
pub struct GuidLe([c_uchar; 16]);

impl FromStr for GuidLe {
    type Err = crate::error::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(Self(
            guid_le_to_slice(s)?
        ))
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SevHashTableEntry {
    guid: GuidLe,
    length: c_ushort,
    hash: Sha256Hash,
}

impl SevHashTableEntry {
    fn new(guid: &str, hash: Sha256Hash) -> Result<Self> {
        Ok(
            Self {
                guid: GuidLe::from_str(guid)?,
                length: std::mem::size_of::<SevHashTableEntry>() as c_ushort,
                hash
            }
        )
    }
}

unsafe impl Zeroable for SevHashTableEntry {

}

unsafe impl Pod for SevHashTableEntry {

}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SevHashTable {
    guid: GuidLe,
    length: c_ushort,
    cmdline: SevHashTableEntry,
    initrd: SevHashTableEntry,
    kernel: SevHashTableEntry,
}

impl SevHashTable {
    fn new(guid: &str,
           cmdline: SevHashTableEntry,
           initrd: SevHashTableEntry,
           kernel: SevHashTableEntry) -> Result<Self> {
        Ok(
            Self {
                guid: GuidLe::from_str(guid)?,
                length: std::mem::size_of::<SevHashTable>() as c_ushort,
                cmdline,
                initrd,
                kernel,
            }
        )
    }
}

unsafe impl Zeroable for SevHashTable {

}

unsafe impl Pod for SevHashTable {

}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PaddedSevHashTable {
    ht: SevHashTable,
    padding: [c_uchar; ((std::mem::size_of::<SevHashTable>() + 15) & !15) -
        std::mem::size_of::<SevHashTable>()],
}

impl PaddedSevHashTable {
    fn new(inner: SevHashTable) -> Self {
        let mut us = PaddedSevHashTable::zeroed();
        us.ht = inner;
        us
    }
}

unsafe impl Zeroable for PaddedSevHashTable {

}

unsafe impl Pod for PaddedSevHashTable {

}

pub struct SevHashes {
    kernel_hash: [u8; U32::USIZE],
    initrd_hash: [u8; U32::USIZE],
    cmdline_hash: [u8; U32::USIZE],
}

impl SevHashes {
    pub fn new(kernel_path: &Path,
               initrd_path: Option<&Path>,
               append: Option<&str>) -> Result<Self> {
        let kernel_hash = sha256_file(kernel_path)?;

        let initrd_hash = if let Some(initrd_path) = initrd_path {
            sha256_file(initrd_path)?
        } else {
            sha256(b"")
        };

        let cmdline_hash = if let Some(append) = append {
            let mut append_bytes = append.trim().as_bytes().to_vec();
            append_bytes.extend_from_slice(b"\x00");
            sha256(&append_bytes)
        } else {
            sha256(b"\x00")
        };

        Ok(
            Self {
                kernel_hash: kernel_hash.to_vec().try_into()
                    .map_err(|_e| conversion("kernel_hash was too big", None))?,
                initrd_hash: initrd_hash.to_vec().try_into()
                    .map_err(|_e| conversion("initrd_hash was too big", None))?,
                cmdline_hash: cmdline_hash.to_vec().try_into()
                    .map_err(|_e| conversion("cmdline_hash was too big", None))?,
            }
        )
    }

    /// Generate the SEV hashes area - this must be *identical* to the way QEMU
    /// generates this info in order for the measurement to match.
    pub fn construct_table(&self) -> Result<Vec<u8>> {
        let padded = PaddedSevHashTable::new(
            SevHashTable::new(
                SEV_HASH_TABLE_HEADER_GUID,
                SevHashTableEntry::new(SEV_CMDLINE_ENTRY_GUID, Sha256Hash(self.cmdline_hash))?,
                SevHashTableEntry::new(SEV_INITRD_ENTRY_GUID, Sha256Hash(self.initrd_hash))?,
                SevHashTableEntry::new(SEV_KERNEL_ENTRY_GUID, Sha256Hash(self.kernel_hash))?,
            )?
        );

        Ok(bytes_of(&padded).to_vec())
    }

    /*
    def construct_page(self, offset: int) -> bytes:
        assert offset < 4096
        hashes_table = self.construct_table()
        page = bytes(offset) + hashes_table + bytes(4096 - offset - len(hashes_table))
        assert len(page) == 4096
        return page
     */
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use crate::common::binary::{fmt_bin_vec_to_hex, fmt_slice_vec_to_hex};
    use crate::guest::measure::sev_hashes::SevHashes;

    const RESOURCES_TEST_DIR: &str = "resources/test/measure";

    #[test]
    fn sev_hashes_new_test() {
        let kernel_path = get_test_path("vmlinuz");
        let append_path = get_test_path("vmlinuz.cmdline");
        let initrd_path = get_test_path("initrd.img");

        let append = fs::read_to_string(append_path)
            .expect("failed to read 'vmlinuz.cmdline'");

        for (
            name, kp, ip, ap,
            exp_kh, exp_ih, exp_ah
        ) in vec![
            (
                "all_args",
                kernel_path.as_path(), Some(initrd_path.as_path()), Some(append.as_str()),
                "d53eb8a5f14acd4f1aec25d5523686787498e2862742cd3020b087a18133740e",
                "39ce25428652ef31aa24f3e94b3469c7a96860f4faad1d26529fb42f97f8a367",
                "b4534934b699c65e5d21c0d1d8ad129163466f904bf0e7512952e2889694b324"
            ),(
                "no_initrd",
                kernel_path.as_path(), None, Some(append.as_str()),
                "d53eb8a5f14acd4f1aec25d5523686787498e2862742cd3020b087a18133740e",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "b4534934b699c65e5d21c0d1d8ad129163466f904bf0e7512952e2889694b324"
            ),(
                "no_append",
                kernel_path.as_path(), Some(initrd_path.as_path()), None,
                "d53eb8a5f14acd4f1aec25d5523686787498e2862742cd3020b087a18133740e",
                "39ce25428652ef31aa24f3e94b3469c7a96860f4faad1d26529fb42f97f8a367",
                "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
            ),
        ] {
            println!("Running test: {}", name);

            let sh = SevHashes::new(kp, ip, ap)
                .expect("failed to construct SevHashes");

            assert_eq!(fmt_slice_vec_to_hex(&sh.kernel_hash), exp_kh);
            assert_eq!(fmt_slice_vec_to_hex(&sh.initrd_hash), exp_ih);
            assert_eq!(fmt_slice_vec_to_hex(&sh.cmdline_hash), exp_ah);
        }
    }

    #[test]
    fn construct_table_test() {
        let kernel_path = get_test_path("vmlinuz");
        let append_path = get_test_path("vmlinuz.cmdline");
        let initrd_path = get_test_path("initrd.img");

        let append = fs::read_to_string(append_path)
            .expect("failed to read 'vmlinuz.cmdline'");

        for (
            name, kp, ip, ap,
            exp
        ) in vec![
            (
                "all_args",
                kernel_path.as_path(), Some(initrd_path.as_path()), Some(append.as_str()),
                "06d63894224fc94cb479a793d411fd21a800d82dd09720bd944caa78e7714d36ab2a3200b4534934b699c65e5d21c0d1d8ad129163466f904bf0e7512952e2889694b32431f7ba442f3ad74b9af141e29169781d320039ce25428652ef31aa24f3e94b3469c7a96860f4faad1d26529fb42f97f8a3673794e74dd2ab7f42b835d5b172d2045b3200d53eb8a5f14acd4f1aec25d5523686787498e2862742cd3020b087a18133740e0000000000000000",
            ),(
                "no_initrd",
                kernel_path.as_path(), None, Some(append.as_str()),
                "06d63894224fc94cb479a793d411fd21a800d82dd09720bd944caa78e7714d36ab2a3200b4534934b699c65e5d21c0d1d8ad129163466f904bf0e7512952e2889694b32431f7ba442f3ad74b9af141e29169781d3200e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8553794e74dd2ab7f42b835d5b172d2045b3200d53eb8a5f14acd4f1aec25d5523686787498e2862742cd3020b087a18133740e0000000000000000",
            ),(
                "no_append",
                kernel_path.as_path(), Some(initrd_path.as_path()), None,
                "06d63894224fc94cb479a793d411fd21a800d82dd09720bd944caa78e7714d36ab2a32006e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d31f7ba442f3ad74b9af141e29169781d320039ce25428652ef31aa24f3e94b3469c7a96860f4faad1d26529fb42f97f8a3673794e74dd2ab7f42b835d5b172d2045b3200d53eb8a5f14acd4f1aec25d5523686787498e2862742cd3020b087a18133740e0000000000000000",
            ),
        ] {
            println!("Running test: {}", name);

            let sh = SevHashes::new(kp, ip, ap)
                .expect("failed to construct SevHashes");

            let table = sh.construct_table()
                .expect("failed to construct_table");

            assert_eq!(fmt_bin_vec_to_hex(&table), exp);
        }
    }

    // Util
    fn get_test_path(path: &str) -> PathBuf {
        let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_path.push(RESOURCES_TEST_DIR);
        test_path.push(path);
        test_path
    }
}