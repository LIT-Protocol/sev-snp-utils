/// This feature has been ported from: https://github.com/IBM/sev-snp-measure
/// full credit goes to the original authors.
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::{validation, Result};
use crate::guest::identity::LaunchDigest;
use crate::guest::measure::gctx::GCTX;
use crate::guest::measure::ovmf::{SectionType, OVMF};
use crate::guest::measure::sev_hashes::SevHashes;
use crate::guest::measure::types::SevMode;
use crate::guest::measure::vcpu_types::CpuType;
use crate::guest::measure::vmsa::VMSA;

use self::ovmf::OvmfSevMetadataSectionDesc;

pub mod gctx;
pub mod ovmf;
pub mod sev_hashes;
pub mod types;
pub mod vcpu_types;
pub mod vmsa;

const PAGE_MASK: usize = 0xfff;

pub fn calc_launch_digest(
    mode: SevMode,
    vcpus: usize,
    vcpu_type: CpuType,
    ovmf_path: &Path,
    kernel_path: Option<&Path>,
    initrd_path: Option<&Path>,
    append: Option<&str>,
) -> Result<Vec<u8>> {
    match mode {
        SevMode::Sev => sev_calc_launch_digest(ovmf_path, kernel_path, initrd_path, append),
        SevMode::SevEs => seves_calc_launch_digest(
            vcpus,
            vcpu_type,
            ovmf_path,
            kernel_path,
            initrd_path,
            append,
        ),
        SevMode::SevSnp => Ok(snp_calc_launch_digest(
            vcpus,
            vcpu_type,
            ovmf_path,
            kernel_path,
            initrd_path,
            append,
        )?
        .to_vec()),
    }
}

pub(crate) fn snp_update_kernel_hashes(
    gctx: &mut GCTX,
    ovmf: &OVMF,
    sev_hashes: &Option<SevHashes>,
    gpa: u64,
    size: u64,
) -> Result<()> {
    if let Some(sev_hashes) = sev_hashes {
        let sev_hashes_table_gpa = ovmf.sev_hashes_table_gpa()? as usize;
        let offset_in_page = sev_hashes_table_gpa & PAGE_MASK;
        let sev_hashes_page = sev_hashes.construct_page(offset_in_page)?;
        if sev_hashes_page.len() != size as usize {
            return Err(validation(
                format!(
                    "hashes page is {} bytes when it should be {size} bytes",
                    sev_hashes_page.len()
                ),
                None,
            ));
        }
        gctx.update_normal_pages(gpa, sev_hashes_page.as_slice())?
    } else {
        gctx.update_zero_pages(gpa, size as usize)?
    }
    Ok(())
}

pub(crate) fn snp_update_section(
    desc: &OvmfSevMetadataSectionDesc,
    gctx: &mut GCTX,
    ovmf: &OVMF,
    sev_hashes: &Option<SevHashes>,
) -> Result<()> {
    match desc.section_type()? {
        SectionType::SnpSecMem => gctx.update_zero_pages(desc.gpa() as u64, desc.size() as usize),
        SectionType::SnpSecrets => gctx.update_secrets_page(desc.gpa() as u64),
        SectionType::CPUID =>
        // TODO: Add VMMType if not vmm_type == VMMType.ec2:
        {
            gctx.update_cpuid_page(desc.gpa() as u64)
        }
        SectionType::SvsmCaa => gctx.update_zero_pages(desc.gpa() as u64, desc.size() as usize),
        SectionType::SnpKernelHashes => snp_update_kernel_hashes(
            gctx,
            ovmf,
            sev_hashes,
            desc.gpa() as u64,
            desc.size() as u64,
        ),
    }
}
pub(crate) fn snp_update_metadata_pages(
    gctx: &mut GCTX,
    ovmf: &OVMF,
    sev_hashes: Option<SevHashes>,
) -> Result<()> {
    for desc in ovmf.metadata_items() {
        snp_update_section(desc, gctx, ovmf, &sev_hashes)?
    }
    // TODO if vmm_type == VMMType.ec2:
    if sev_hashes.is_some() && !ovmf.has_metadata_section(SectionType::SnpKernelHashes) {
        return Err(validation(
            "Kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section",
            None,
        ));
    }
    Ok(())
}

pub fn snp_calc_launch_digest(
    vcpus: usize,
    vcpu_type: CpuType,
    ovmf_path: &Path,
    kernel_path: Option<&Path>,
    initrd_path: Option<&Path>,
    append: Option<&str>,
) -> Result<LaunchDigest> {
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

    let vmsa = VMSA::new(SevMode::SevSnp, ovmf.sev_es_reset_eip()?, vcpu_type);
    for page in vmsa.pages(vcpus) {
        gctx.update_vmsa_page(&page[..])?;
    }

    Ok(gctx.take_ld())
}

pub(crate) fn seves_calc_launch_digest(
    vcpus: usize,
    vcpu_type: CpuType,
    ovmf_path: &Path,
    kernel_path: Option<&Path>,
    initrd_path: Option<&Path>,
    append: Option<&str>,
) -> Result<Vec<u8>> {
    let mut launch_hash = Sha256::new();
    let ovmf = OVMF::from_path(ovmf_path)?;
    launch_hash.update(ovmf.data());

    if let Some(kernel_path) = kernel_path {
        if !ovmf.is_sev_hashes_table_supported() {
            return Err(validation(
                format!(
                    "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
                ),
                None,
            ));
        }
        let sev_hashes_table =
            SevHashes::new(kernel_path, initrd_path, append)?.construct_table()?;
        launch_hash.update(&sev_hashes_table);
    }
    let vmsa = VMSA::new(SevMode::SevEs, ovmf.sev_es_reset_eip()?, vcpu_type);
    for page in vmsa.pages(vcpus) {
        launch_hash.update(&page);
    }

    Ok(launch_hash.finalize().to_vec())
}

pub(crate) fn sev_calc_launch_digest(
    ovmf_path: &Path,
    kernel_path: Option<&Path>,
    initrd_path: Option<&Path>,
    append: Option<&str>,
) -> Result<Vec<u8>> {
    let mut launch_hash = Sha256::new();
    let ovmf = OVMF::from_path(ovmf_path)?;
    launch_hash.update(ovmf.data());

    if let Some(kernel_path) = kernel_path {
        if !ovmf.is_sev_hashes_table_supported() {
            return Err(validation(
                format!(
                    "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
                ),
                None,
            ));
        }
        let sev_hashes_table =
            SevHashes::new(kernel_path, initrd_path, append)?.construct_table()?;
        launch_hash.update(&sev_hashes_table);
    }

    Ok(launch_hash.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use crate::common::binary::fmt_bin_vec_to_hex;
    use crate::{calc_launch_digest, CpuType, SevMode};
    use std::fs;
    use std::path::PathBuf;
    use std::str::FromStr;

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
                "f436f03de04bc36add418865b7ad2dc15f206decaed33af390c276a89ce458c8f5a0978b6268b2d55af2971f5f86f98e", // this is what sev-snp-measure outputs for these params
            ), (
                "sev_snp_all_args_milan", SevMode::SevSnp, 8, CpuType::EpycMilan,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), Some(append.as_str()),
                "e2eb7c6cb62216ea8db4f4b5d85fc5ca339e724dee4f433b6db06383abc2d6161eae5ad112f2b1dcdc9cce74f2d271ef",
            ), (
                "sev_snp_no_initrd", SevMode::SevSnp, 4, CpuType::EpycV4,
                Some(kernel_path.as_path()), None, Some(append.as_str()),
                "49c1576318efeff1eeb561861bd46bc93efee7907700086016e601b5e3493c8897c695f47be4aaf36caa19fba40bd6a3",
            ), (
                "sev_snp_no_append", SevMode::SevSnp, 4, CpuType::EpycV4,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), None,
                "cdc44fd6503e7f94acd0a0253193bf66c482f8d4838741db18a51c280f01667ccf0499790eeec89231aca2a52eb50ff9",
            ), (
                "sev_snp_no_optional", SevMode::SevSnp, 4, CpuType::EpycV4,
                None, None, None,
                "65f68550aead630a4ed5a2f84b4a46720ea129dbd5e571134b473562d0c64fa4e3ea81a3f9574d0793492e02c2afe3de",
            ), (
                "sev_es_all_args", SevMode::SevEs, 8, CpuType::EpycRome,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), Some(append.as_str()),
                "b6af4ee9fccd73c09d4bc7bced680c3e256d1111cc79024dd4985baa0aa4933b",
            ), (
                "sev_all_args", SevMode::Sev, 12, CpuType::EpycRome,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), Some(append.as_str()),
                "336ad8a4d0806ed2c19d9b8253504f0d3d95562ca71c31f958924ff1b49876d2",
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
    #[test]
    fn calc_launch_digest_manual_test() {
        // /usr/bin/python3 /home/adam/git/virtee/sev-snp-measure/sev-snp-measure.py
        // --mode snp --vcpus 4 --vcpu-type EPYC-v4 --ovmf amd/OVMF.fd --kernel ./guest-vmlinuz --initrd guest-initrd.img
        //  --append 'console=ttyS0 earlyprintk=serial root=/dev/disk/by-uuid/bbf61fb4-b6ce-44af-ac57-1850cd708965 usbcore.nousb litos.build_id=5761633e litos.type=prov litos.env=dev litos.roothash=40a84c7f2ecf13d5c9b31cb50ab5d79ac9b9cf59a35d25fdf4034ce9caf062e76163dfd21064ff3cf27df72577ec880030bf3580a0fe7db32698bab70bec35cf litos.varhash=f85184ec9a09b8dbb1154c107c8f49f1297df17efe352ae55d92824998d8fc2a6d419c680cacce0d5ffcddf5377be8a11a3effc739c097d0bebd074e84c78883 litos.opt_ro=0 litos.opt_users=1 litos.opt_ssh=1'
        // --guest-features=0x1 --vmm-type=QEMU --output-format=hex
        let ovmf_path =
            PathBuf::from_str("/var/lit/os/guest/templates/dev/node/372ea29f/amd/OVMF.fd").unwrap(); // note: OVMF must have hashes table built in
        let kernel_path =
            PathBuf::from_str("/var/lit/os/guest/templates/dev/node/372ea29f/guest-vmlinuz")
                .unwrap();
        let append_path = PathBuf::from_str(
            "/var/lit/os/guest/templates/dev/node/372ea29f/guest-vmlinuz.cmdline",
        )
        .unwrap();
        let initrd_path =
            PathBuf::from_str("/var/lit/os/guest/templates/dev/node/372ea29f/guest-initrd.img")
                .unwrap();

        let append = fs::read_to_string(&append_path)
            .expect(format!("failed to read '{:?}'", &append_path).as_str());

        for (name, mode, vcpus, vcpu_type, kp, ip, ap, exp) in vec![
            (
                "like_sev_snp_measure", SevMode::SevSnp, 4, CpuType::EpycV4,
                Some(kernel_path.as_path()), Some(initrd_path.as_path()), Some(append.as_str()),
                "7dd49911d409d9b51141a45e886e32c84e27a02da9de0f33c2c009dc864c66f1492ac66fb7e927d112ab9eedb32907b3", // this is what sev-snp-measure outputs for these params
            )
        ] {
            println!("Running test: {}", name);

            let measure =
                calc_launch_digest(mode, vcpus, vcpu_type, ovmf_path.as_path(), kp, ip, ap)
                    .expect("failed to call calc_launch_digest");

            assert_eq!(fmt_bin_vec_to_hex(&measure), exp);
        }
    }
}
