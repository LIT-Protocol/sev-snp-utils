use std::{
    io::{self, Read},
};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::common::binary::{fmt_bin_vec_to_decimal, fmt_bin_vec_to_hex, read_exact_to_bin_vec};

const POLICY_DEBUG_SHIFT: u64 = 19;
const POLICY_MIGRATE_MA_SHIFT: u64 =	18;
const POLICY_SMT_SHIFT: u64 = 16;
const POLICY_ABI_MAJOR_SHIFT: u64 = 8;
const POLICY_ABI_MINOR_SHIFT: u64 = 0;

const POLICY_DEBUG_MASK: u64 = 1 << (POLICY_DEBUG_SHIFT);
const POLICY_MIGRATE_MA_MASK: u64 = 1 << (POLICY_MIGRATE_MA_SHIFT);
const POLICY_SMT_MASK: u64 = 1 << (POLICY_SMT_SHIFT);
const POLICY_ABI_MAJOR_MASK: u64 = 0xFF << (POLICY_ABI_MAJOR_SHIFT);
const POLICY_ABI_MINOR_MASK: u64 = 0xFF << (POLICY_ABI_MINOR_SHIFT);

const SIG_ALGO_ECDSA_P384_SHA384: u32 = 0x1;

const PLATFORM_INFO_SMT_EN_SHIFT: u64 = 0;
const PLATFORM_INFO_SMT_EN_MASK: u64 = 1 << (PLATFORM_INFO_SMT_EN_SHIFT);

const AUTHOR_KEY_EN_SHIFT: u64 =	0;
const AUTHOR_KEY_EN_MASK: u64 = 1 << (AUTHOR_KEY_EN_SHIFT);

/*
reference: https://github.com/AMDESE/sev-guest/blob/main/include/attestation.h

union tcb_version {
	struct {
		uint8_t boot_loader;
		uint8_t tee;
		uint8_t reserved[4];
		uint8_t snp;
		uint8_t microcode;
	};
	uint64_t raw;
};

struct signature {
	uint8_t r[72];
	uint8_t s[72];
	uint8_t reserved[512-144];
};

struct attestation_report {
	uint32_t          version;			/* 0x000 */
	uint32_t          guest_svn;			/* 0x004 */
	uint64_t          policy;			/* 0x008 */
	uint8_t           family_id[16];		/* 0x010 */
	uint8_t           image_id[16];			/* 0x020 */
	uint32_t          vmpl;				/* 0x030 */
	uint32_t          signature_algo;		/* 0x034 */
	union tcb_version platform_version;		/* 0x038 */
	uint64_t          platform_info;		/* 0x040 */
	uint32_t          flags;			/* 0x048 */
	uint32_t          reserved0;			/* 0x04C */
	uint8_t           report_data[64];		/* 0x050 */
	uint8_t           measurement[48];		/* 0x090 */
	uint8_t           host_data[32];		/* 0x0C0 */
	uint8_t           id_key_digest[48];		/* 0x0E0 */
	uint8_t           author_key_digest[48];	/* 0x110 */
	uint8_t           report_id[32];		/* 0x140 */
	uint8_t           report_id_ma[32];		/* 0x160 */
	union tcb_version reported_tcb;			/* 0x180 */
	uint8_t           reserved1[24];		/* 0x188 */
	uint8_t           chip_id[64];			/* 0x1A0 */
	uint8_t           reserved2[192];		/* 0x1E0 */
	struct signature  signature;			/* 0x2A0 */
};
 */

#[allow(dead_code)]
pub struct TcbVersion {
    boot_loader: u8,
    tee: u8,
    reserved: Vec<u8>,
    snp: u8,
    microcode: u8,
    raw: Vec<u8>,
}

#[allow(dead_code)]
impl TcbVersion {
    fn from_reader(mut rdr: impl Read) -> io::Result<Self> {
        let boot_loader = rdr.read_u8()?;
        let tee = rdr.read_u8()?;
        let reserved = read_exact_to_bin_vec(&mut rdr, 4)?;
        let snp = rdr.read_u8()?;
        let microcode = rdr.read_u8()?;
        let raw = vec![
            boot_loader, tee,
            reserved[0], reserved[1], reserved[2], reserved[3],
            snp, microcode,
        ];

        Ok(TcbVersion {
            boot_loader,
            tee,
            reserved,
            snp,
            microcode,
            raw,
        })
    }

    pub fn raw_decimal(&self) -> String {
        fmt_bin_vec_to_decimal(self.raw.as_ref())
    }
}

#[allow(dead_code)]
pub struct BuildVersion {
    build: u8,
    minor: u8,
    major: u8,
    reserved: u8,
}

#[allow(dead_code)]
impl BuildVersion {
    fn from_reader(mut rdr: impl Read) -> io::Result<Self> {
        let build = rdr.read_u8()?;
        let minor = rdr.read_u8()?;
        let major = rdr.read_u8()?;
        let reserved = rdr.read_u8()?;

        Ok(BuildVersion {
            build,
            minor,
            major,
            reserved,
        })
    }
}

#[allow(dead_code)]
pub struct Signature {
    r: Vec<u8>,
    s: Vec<u8>,
    reserved: Vec<u8>,
}

#[allow(dead_code)]
impl Signature {
    fn from_reader(mut rdr: impl Read) -> io::Result<Self> {
        let r = read_exact_to_bin_vec(&mut rdr, 72)?;
        let s = read_exact_to_bin_vec(&mut rdr, 72)?;
        let reserved = read_exact_to_bin_vec(&mut rdr, 144)?;

        Ok(Signature {
            r,
            s,
            reserved,
        })
    }

    pub fn r_hex(&self) -> String {
        fmt_bin_vec_to_hex(self.r.as_ref())
    }

    pub fn s_hex(&self) -> String {
        fmt_bin_vec_to_hex(self.s.as_ref())
    }
}

#[allow(dead_code)]
pub struct AttestationReport {
    version: u32,
    guest_svn: u32,
    policy: u64,
    family_id: Vec<u8>,
    image_id: Vec<u8>,
    vmpl: u32,
    signature_algo: u32,
    platform_version: TcbVersion,
    platform_info: u64,
    flags: u32,
    reserved0: u32,
    report_data: Vec<u8>,
    measurement: Vec<u8>,
    host_data: Vec<u8>,
    id_key_digest: Vec<u8>,
    author_key_digest: Vec<u8>,
    report_id: Vec<u8>,
    report_id_ma: Vec<u8>,
    reported_tcb: TcbVersion,
    reserved1: Vec<u8>,
    chip_id: Vec<u8>,
    committed_tcb: TcbVersion,
    current_build: BuildVersion,
    committed_build: BuildVersion,
    launch_tcb: TcbVersion,
    reserved2: Vec<u8>,
    signature: Signature,
}

#[allow(dead_code)]
impl AttestationReport {
    fn from_reader(mut rdr: impl Read) -> io::Result<Self> {
        let version = rdr.read_u32::<LittleEndian>()?;
        let guest_svn = rdr.read_u32::<LittleEndian>()?;
        let policy = rdr.read_u64::<LittleEndian>()?;
        let family_id = read_exact_to_bin_vec(&mut rdr, 16)?;
        let image_id = read_exact_to_bin_vec(&mut rdr, 16)?;
        let vmpl = rdr.read_u32::<LittleEndian>()?;
        let signature_algo = rdr.read_u32::<LittleEndian>()?;
        let platform_version = TcbVersion::from_reader(&mut rdr)?;
        let platform_info = rdr.read_u64::<LittleEndian>()?;
        let flags = rdr.read_u32::<LittleEndian>()?;
        let reserved0 = rdr.read_u32::<LittleEndian>()?;
        let report_data = read_exact_to_bin_vec(&mut rdr, 64)?;
        let measurement = read_exact_to_bin_vec(&mut rdr, 48)?;
        let host_data = read_exact_to_bin_vec(&mut rdr, 32)?;
        let id_key_digest = read_exact_to_bin_vec(&mut rdr, 48)?;
        let author_key_digest = read_exact_to_bin_vec(&mut rdr, 48)?;
        let report_id = read_exact_to_bin_vec(&mut rdr, 32)?;
        let report_id_ma = read_exact_to_bin_vec(&mut rdr, 32)?;
        let reported_tcb = TcbVersion::from_reader(&mut rdr)?;
        let reserved1 = read_exact_to_bin_vec(&mut rdr, 24)?;
        let chip_id = read_exact_to_bin_vec(&mut rdr, 64)?;
        let committed_tcb = TcbVersion::from_reader(&mut rdr)?;
        let current_build = BuildVersion::from_reader(&mut rdr)?;
        let committed_build = BuildVersion::from_reader(&mut rdr)?;
        let launch_tcb = TcbVersion::from_reader(&mut rdr)?;
        let reserved2 = read_exact_to_bin_vec(&mut rdr, 168)?;
        let signature = Signature::from_reader(&mut rdr)?;

        Ok(AttestationReport {
            version,
            guest_svn,
            policy,
            family_id,
            image_id,
            vmpl,
            signature_algo,
            platform_version,
            platform_info,
            flags,
            reserved0,
            report_data,
            measurement,
            host_data,
            id_key_digest,
            author_key_digest,
            report_id,
            report_id_ma,
            reported_tcb,
            reserved1,
            chip_id,
            committed_tcb,
            current_build,
            committed_build,
            launch_tcb,
            reserved2,
            signature,
        })
    }

    pub fn policy_debug_allowed(&self) -> bool {
        self.policy & POLICY_DEBUG_MASK > 0
    }

    pub fn policy_ma_allowed(&self) -> bool {
        self.policy & POLICY_MIGRATE_MA_MASK > 0
    }

    pub fn policy_smt_allowed(&self) -> bool {
        self.policy & POLICY_SMT_MASK > 0
    }

    pub fn policy_min_abi_major(&self) -> u64 {
        (self.policy & POLICY_ABI_MAJOR_MASK) >> POLICY_ABI_MAJOR_SHIFT
    }

    pub fn policy_min_abi_minor(&self) -> u64 {
        (self.policy & POLICY_ABI_MINOR_MASK) >> POLICY_ABI_MINOR_SHIFT
    }

    pub fn signature_algo_is_ecdsa_p384_sha384(&self) -> bool {
        self.signature_algo == SIG_ALGO_ECDSA_P384_SHA384
    }

    pub fn platform_smt_enabled(&self) -> bool {
        self.platform_info & PLATFORM_INFO_SMT_EN_MASK > 0
    }

    pub fn platform_author_key_enabled(&self) -> bool {
        self.platform_info & AUTHOR_KEY_EN_MASK > 0
    }

    pub fn report_data_hex(&self) -> String {
        fmt_bin_vec_to_hex(self.report_data.as_ref())
    }

    pub fn measurement_hex(&self) -> String {
        fmt_bin_vec_to_hex(self.measurement.as_ref())
    }

    pub fn report_id_hex(&self) -> String {
        fmt_bin_vec_to_hex(self.report_id.as_ref())
    }

    pub fn chip_id_hex(&self) -> String {
        fmt_bin_vec_to_hex(self.chip_id.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::path::PathBuf;

    use crate::guest::attestation::report::AttestationReport;

    #[test]
    fn attestation_report_file_test() {
        let mut test_file = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        test_file.push("resources/test/guest_report.bin");

        let file = File::open(&test_file).unwrap();

        let report = AttestationReport::from_reader(file).unwrap();

        assert_eq!(report.version, 2);
        assert_eq!(report.guest_svn, 0);
        assert_eq!(report.policy, 0x30000);
        assert_eq!(report.policy_debug_allowed(), false);
        assert_eq!(report.policy_ma_allowed(), false);
        assert_eq!(report.policy_smt_allowed(), true);
        assert_eq!(report.policy_min_abi_major(), 0);
        assert_eq!(report.policy_min_abi_minor(), 0);
        assert_eq!(report.family_id, vec![0; 16]);
        assert_eq!(report.image_id, vec![0; 16]);
        assert_eq!(report.vmpl, 0);
        assert_eq!(report.signature_algo, 1);
        assert_eq!(report.signature_algo_is_ecdsa_p384_sha384(), true);

        assert_eq!(report.platform_version.boot_loader, 2);
        assert_eq!(report.platform_version.tee, 0);
        assert_eq!(report.platform_version.reserved, vec![0; 4]);
        assert_eq!(report.platform_version.snp, 6);
        assert_eq!(report.platform_version.microcode, 115);
        assert_eq!(report.platform_version.raw_decimal(), "02000000000006115");

        assert_eq!(report.platform_info, 0x1);
        assert_eq!(report.platform_smt_enabled(), true);
        assert_eq!(report.platform_author_key_enabled(), true);
        assert_eq!(report.flags, 0);
        assert_eq!(report.reserved0, 0);
        assert_eq!(report.report_data_hex(),
                   "e1c112ff908febc3b98b1693a6cd3564eaf8e5e6ca629d084d9f0eba99247cacdd72e369ff8941397c2807409ff66be64be908da17ad7b8a49a2a26c0e8086aa");
        assert_eq!(report.measurement_hex(),
                   "7659528961bc689a43f5be14ed063fe1c26058e5a4f0bbbfd3944aa15032404c5afb731f7826c9a007f2ad63c813b04c");
        assert_eq!(report.host_data, vec![0; 32]);
        assert_eq!(report.id_key_digest, vec![0; 48]);
        assert_eq!(report.author_key_digest, vec![0; 48]);
        assert_eq!(report.report_id_hex(),
                   "d1c1273910e39b8286661767afa497dd02465cc8e0a7082c04cf576169407e6e");
        assert_eq!(report.report_id_ma, vec![255; 32]);

        assert_eq!(report.reported_tcb.boot_loader, 2);
        assert_eq!(report.reported_tcb.tee, 0);
        assert_eq!(report.reported_tcb.reserved, vec![0; 4]);
        assert_eq!(report.reported_tcb.snp, 5);
        assert_eq!(report.reported_tcb.microcode, 115);
        assert_eq!(report.reported_tcb.raw_decimal(), "02000000000005115");

        assert_eq!(report.reserved1, vec![0; 24]);
        assert_eq!(report.chip_id_hex(),
                   "9e1235cce6f3e507b66a9d3f2199a325cd0be17c6c50fd55c284ceff993dbf6c7e32fa16a76521bf6b78cc9ca482e572bde70e8c9f1bdfcb8267dea8e11ff77e");

        assert_eq!(report.committed_tcb.boot_loader, 2);
        assert_eq!(report.committed_tcb.tee, 0);
        assert_eq!(report.committed_tcb.reserved, vec![0; 4]);
        assert_eq!(report.committed_tcb.snp, 5);
        assert_eq!(report.committed_tcb.microcode, 115);
        assert_eq!(report.committed_tcb.raw_decimal(), "02000000000005115");

        assert_eq!(report.current_build.build, 3);
        assert_eq!(report.current_build.minor, 51);
        assert_eq!(report.current_build.major, 1);
        assert_eq!(report.current_build.reserved, 0);

        assert_eq!(report.committed_build.build, 6);
        assert_eq!(report.committed_build.minor, 49);
        assert_eq!(report.committed_build.major, 1);
        assert_eq!(report.committed_build.reserved, 0);

        assert_eq!(report.launch_tcb.boot_loader, 2);
        assert_eq!(report.launch_tcb.tee, 0);
        assert_eq!(report.launch_tcb.reserved, vec![0; 4]);
        assert_eq!(report.launch_tcb.snp, 5);
        assert_eq!(report.launch_tcb.microcode, 115);
        assert_eq!(report.launch_tcb.raw_decimal(), "02000000000005115");

        assert_eq!(report.reserved2, vec![0; 168]);

        assert_eq!(report.signature.r_hex(),
                   "ad822d4e2c64aede8fecc4057f0754c1316a64d5c6e9aabcdf0d20889fb42a3bce443b561e820febd19519bb3e091b8d000000000000000000000000000000000000000000000000");
        assert_eq!(report.signature.s_hex(),
                   "02cdeb225f047c25b8a2330bdcab6df7d4f1e773f6474787578e5ed753186b1747888d72b26c6aefa40e6357dca3cb92000000000000000000000000000000000000000000000000");
        assert_eq!(report.signature.reserved, vec![0; 144]);
    }
}