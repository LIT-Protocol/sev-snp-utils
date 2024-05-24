/// This feature has been ported from: https://github.com/IBM/sev-snp-measure
/// full credit goes to the original authors.

use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{Result,validation};
use crate::guest::identity::LaunchDigest;
use crate::guest::measure::gctx::GCTX;
use crate::guest::measure::ovmf::{OVMF, SectionType};
use crate::guest::measure::sev_hashes::SevHashes;
use crate::guest::measure::types::SevMode;
use crate::guest::measure::vcpu_types::CpuType;
use crate::guest::measure::vmsa::VSMA;

use self::ovmf::OvmfSevMetadataSectionDesc;

pub mod types;
pub mod gctx;
pub mod ovmf;
pub mod vmsa;
pub mod vcpu_types;
pub mod sev_hashes;

const PAGE_MASK: usize = 0xfff;

pub fn calc_launch_digest(mode: SevMode,
                          vcpus: usize,
                          vcpu_type: CpuType,
                          ovmf_path: &Path,
                          kernel_path: Option<&Path>,
                          initrd_path: Option<&Path>,
                          append: Option<&str>) -> Result<Vec<u8>> {
    match mode {
        SevMode::Sev => sev_calc_launch_digest(ovmf_path,
                                               kernel_path, initrd_path, append),
        SevMode::SevEs => seves_calc_launch_digest(vcpus, vcpu_type, ovmf_path,
                                                   kernel_path, initrd_path, append),
        SevMode::SevSnp => Ok(
            snp_calc_launch_digest(vcpus, vcpu_type, ovmf_path,
                                   kernel_path, initrd_path, append)?.to_vec()
        ),
    }
}

pub(crate) fn snp_update_kernel_hashes(gctx: &mut GCTX, ovmf: &OVMF, sev_hashes: &Option<SevHashes>, gpa: u64, size: u64) -> Result<()> {
    if let Some(sev_hashes) = sev_hashes {
    let sev_hashes_table_gpa = ovmf.sev_hashes_table_gpa()? as usize;
    let offset_in_page = sev_hashes_table_gpa & PAGE_MASK;
    let sev_hashes_page = sev_hashes.construct_page(offset_in_page)?;
    if sev_hashes_page.len() != size as usize {
        return Err(validation(format!("hashes page is {} bytes when it should be {size} bytes",sev_hashes_page.len()),None))
    }
        gctx.update_normal_pages(gpa, sev_hashes_page.as_slice())?
    }
    else {
        gctx.update_zero_pages(gpa, size as usize)?
    }
    Ok(())
}

pub(crate) fn snp_update_section(desc: &OvmfSevMetadataSectionDesc, gctx: &mut GCTX, ovmf: &OVMF, sev_hashes: &Option<SevHashes>) -> Result<()> {
    match desc.section_type()? {
        SectionType::SnpSecMem =>
            gctx.update_zero_pages(desc.gpa() as u64, desc.size() as usize),
        SectionType::SnpSecrets =>
            gctx.update_secrets_page(desc.gpa() as u64),
        SectionType::CPUID =>
            // TODO: Add VMMType if not vmm_type == VMMType.ec2:
            gctx.update_cpuid_page(desc.gpa() as u64),
        SectionType::SnpKernelHashes =>
            snp_update_kernel_hashes(gctx, ovmf, sev_hashes, desc.gpa() as u64, desc.size() as u64)
    }
}
pub(crate) fn snp_update_metadata_pages(gctx: &mut GCTX, ovmf: &OVMF, sev_hashes: Option<SevHashes>) -> Result<()> {
    for desc in ovmf.metadata_items() {
            snp_update_section(desc, gctx, ovmf, &sev_hashes)?
        }
        // TODO if vmm_type == VMMType.ec2:
        if sev_hashes.is_some() && !ovmf.has_metadata_section(SectionType::SnpKernelHashes){
            return Err(validation("Kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section",None))
        }
    Ok(())
}

pub fn snp_calc_launch_digest(vcpus: usize,
                              vcpu_type: CpuType,
                              ovmf_path: &Path,
                              kernel_path: Option<&Path>,
                              initrd_path: Option<&Path>,
                              append: Option<&str>) -> Result<LaunchDigest> {
    let ovmf = OVMF::from_path(ovmf_path)?;

    let mut gctx = GCTX::new();
    // TODO:  https://github.com/virtee/sev-snp-measure/blob/9dabc4b6a853ec5a41b20d899ae2b68d8f0b81c0/sevsnpmeasure/guest.py#L100
    // add precomputed ovmf hash optional 
    gctx.update_normal_pages(ovmf.gpa(), ovmf.data())?;

    let mut sev_hashes = None;
    if let Some(kernel_path) = kernel_path {
        sev_hashes = Some(SevHashes::new(kernel_path, initrd_path, append)?);
    }

    snp_update_metadata_pages(&mut gctx, &ovmf, sev_hashes)?;

    let vmsa = VSMA::new(SevMode::SevSnp,
                         ovmf.sev_es_reset_eip()?, vcpu_type);
    for page in vmsa.pages(vcpus) {
        gctx.update_vmsa_page(&page[..])?;
    }

    Ok(gctx.take_ld())
}

pub(crate) fn seves_calc_launch_digest(vcpus: usize,
                                       vcpu_type: CpuType,
                                       ovmf_path: &Path,
                                       kernel_path: Option<&Path>,
                                       initrd_path: Option<&Path>,
                                       append: Option<&str>) -> Result<Vec<u8>> {
    let mut launch_hash = Sha256::new();
    let ovmf = OVMF::from_path(ovmf_path)?;
    launch_hash.update(ovmf.data());

    if let Some(kernel_path) = kernel_path {
        if !ovmf.is_sev_hashes_table_supported(){
            return Err(validation(format!("Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"),None))
        }
        let sev_hashes_table = SevHashes::new(kernel_path, initrd_path, append)?
            .construct_table()?;
        launch_hash.update(&sev_hashes_table);
    }
    let vmsa = VSMA::new(SevMode::SevEs,
                         ovmf.sev_es_reset_eip()?, vcpu_type);
    for page in vmsa.pages(vcpus) {
        launch_hash.update(&page);
    }

    Ok(launch_hash.finalize().to_vec())
}

pub(crate) fn sev_calc_launch_digest(ovmf_path: &Path,
                                     kernel_path: Option<&Path>,
                                     initrd_path: Option<&Path>,
                                     append: Option<&str>) -> Result<Vec<u8>> {
    let mut launch_hash = Sha256::new();
    let ovmf = OVMF::from_path(ovmf_path)?;
    launch_hash.update(ovmf.data());

    if let Some(kernel_path) = kernel_path {
        if !ovmf.is_sev_hashes_table_supported(){
            return Err(validation(format!("Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"),None))
        }
        let sev_hashes_table = SevHashes::new(kernel_path, initrd_path, append)?
            .construct_table()?;
        launch_hash.update(&sev_hashes_table);
    }

    Ok(launch_hash.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use crate::{calc_launch_digest, SevMode, CpuType};
    use crate::common::binary::fmt_bin_vec_to_hex;

    const RESOURCES_TEST_DIR: &str = "resources/test/measure";

    #[test]
    fn calc_launch_digest_test() {
        let ovmf_path = get_test_path("ovmf_AmdSev_suffix.bin"); // note: OVMF must have hashes table built in
        let kernel_path = get_test_path("vmlinuz");
        let append_path = get_test_path("vmlinuz.cmdline");
        let initrd_path = get_test_path("initrd.img");

        let append = fs::read_to_string(&append_path)
            .expect(format!("failed to read '{:?}'", &append_path).as_str());

        for (
            name, mode, vcpus, vcpu_type,
            kp, ip, ap,
            exp
        ) in vec![
            (
                "sev_snp_all_args", SevMode::SevSnp, 4, CpuType::EpycV4,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), Some(append.as_str()),
                "29da869e16a408cee99fe28adea700d51bc210a06cc2414742688000adb92534f72269ed7d3b09016014c46b05e10a15",
            ), (
                "sev_snp_all_args_milan", SevMode::SevSnp, 8, CpuType::EpycMilan,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), Some(append.as_str()),
                "1b4585fc9bf8cdf791e0de5cd799af7fa051fffce11c998a6001f440e302c1c89d5b845d931976ff9c28adf41d528454",
            ), (
                "sev_snp_no_initrd", SevMode::SevSnp, 4, CpuType::EpycV4,
                Some(kernel_path.as_path()), None, Some(append.as_str()),
                "63df03ed0226738ab2149496123e9f0cd18e83c8caf935a8a7b99d553dbfd144b1d209440299b042625680ce2134e237",
            ), (
                "sev_snp_no_append", SevMode::SevSnp, 4, CpuType::EpycV4,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), None,
                "4c066bf73f08697ede6a0a96b6d6e57598f60c4e2615c28a4156dee116375ac9e278ab1c088a7b6be4b1a321ea16c4a2",
            ), (
                "sev_snp_no_optional", SevMode::SevSnp, 4, CpuType::EpycV4,
                None, None, None,
                "09f8c50bf2400536dd4d9c4b66a87843cf2a37174db035ac2cb48929731ffca9d0a132aff4a5729f61a4fbf7f70df2af",
            ), (
                "sev_es_all_args", SevMode::SevEs, 8, CpuType::EpycRome,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), Some(append.as_str()),
                "35cd6f65cb2e5f2a14865481bdbcadab40e1de852c921a70c2566f2fba2fa134",
            ), (
                "sev_all_args", SevMode::Sev, 12, CpuType::EpycRome,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), Some(append.as_str()),
                "ac1fda9e754c70915051aec47ab3738ff22ccff063ebbbf047884bbb061ec0d1",
            ),
        ] {
            println!("Running test: {}", name);

            let measure = calc_launch_digest(mode, vcpus, vcpu_type, ovmf_path.as_path(),
                                             kp, ip, ap)
                .expect("failed to call calc_launch_digest");

            assert_eq!(fmt_bin_vec_to_hex(&measure), exp);
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