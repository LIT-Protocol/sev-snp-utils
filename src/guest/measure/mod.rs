use std::path::Path;

use sha2::{Digest, Sha256};

use crate::error::Result;
use crate::guest::measure::gctx::GCTX;
use crate::guest::measure::ovmf::{OVMF, SectionType};
use crate::guest::measure::sev_hashes::SevHashes;
use crate::guest::measure::types::SevMode;
use crate::guest::measure::vcpu_types::CpuType;
use crate::guest::measure::vmsa::VSMA;

pub mod types;
pub mod gctx;
pub mod ovmf;
pub mod vmsa;
pub mod vcpu_types;
pub mod sev_hashes;

const PAGE_MASK: usize = 0xfff;

pub fn calc_launch_digest(mode: SevMode, vcpus: usize,
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
        SevMode::SevSnp => snp_calc_launch_digest(vcpus, vcpu_type, ovmf_path,
                                                  kernel_path, initrd_path, append),
    }
}

pub(crate) fn snp_update_metadata_pages(gctx: &mut GCTX, ovmf: &OVMF) -> Result<()> {
    for desc in ovmf.metadata_items() {
        match desc.section_type()? {
            SectionType::SnpSecMem =>
                gctx.update_zero_pages(desc.gpa() as u64, desc.size() as usize)?,
            SectionType::SnpSecrets =>
                gctx.update_secrets_page(desc.gpa() as u64)?,
            SectionType::CPUID =>
                gctx.update_cpuid_page(desc.gpa() as u64)?
        }
    }

    Ok(())
}

pub(crate) fn snp_calc_launch_digest(vcpus: usize,
                                     vcpu_type: CpuType,
                                     ovmf_path: &Path,
                                     kernel_path: Option<&Path>,
                                     initrd_path: Option<&Path>,
                                     append: Option<&str>) -> Result<Vec<u8>> {
    let ovmf = OVMF::from_path(ovmf_path)?;

    let mut gctx = GCTX::new();
    gctx.update_normal_pages(ovmf.gpa(), ovmf.data())?;

    if let Some(kernel_path) = kernel_path {
        let sev_hashes_table_gpa = ovmf.sev_hashes_table_gpa()? as usize;
        let offset_in_page = sev_hashes_table_gpa & PAGE_MASK;
        let sev_hashes_page_gpa = sev_hashes_table_gpa & !PAGE_MASK;
        let sev_hashes = SevHashes::new(kernel_path, initrd_path, append)?;
        let sev_hashes_page = sev_hashes.construct_page(offset_in_page)?;
        gctx.update_normal_pages(sev_hashes_page_gpa as u64, &sev_hashes_page[..])?;
    }

    snp_update_metadata_pages(&mut gctx, &ovmf)?;

    let vmsa = VSMA::new(SevMode::SevSnp,
                         ovmf.sev_es_reset_eip()?, vcpu_type);
    for page in vmsa.pages(vcpus) {
        gctx.update_vmsa_page(&page[..])?;
    }

    Ok(gctx.ld().to_vec())
}

pub(crate) fn seves_calc_launch_digest(vcpus: usize,
                                       vcpu_type: CpuType,
                                       ovmf_path: &Path,
                                       kernel_path: Option<&Path>,
                                       initrd_path: Option<&Path>,
                                       append: Option<&str>) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    let ovmf = OVMF::from_path(ovmf_path)?;
    hasher.update(ovmf.data());

    if let Some(kernel_path) = kernel_path {
        let sev_hashes_table = SevHashes::new(kernel_path, initrd_path, append)?
            .construct_table()?;
        hasher.update(&sev_hashes_table);
    }
    let vmsa = VSMA::new(SevMode::SevEs,
                         ovmf.sev_es_reset_eip()?, vcpu_type);
    for page in vmsa.pages(vcpus) {
        hasher.update(&page);
    }

    Ok(hasher.finalize().to_vec())
}

pub(crate) fn sev_calc_launch_digest(ovmf_path: &Path,
                                     kernel_path: Option<&Path>,
                                     initrd_path: Option<&Path>,
                                     append: Option<&str>) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    let ovmf = OVMF::from_path(ovmf_path)?;
    hasher.update(ovmf.data());

    if let Some(kernel_path) = kernel_path {
        let sev_hashes_table = SevHashes::new(kernel_path, initrd_path, append)?
            .construct_table()?;
        hasher.update(&sev_hashes_table);
    }

    Ok(hasher.finalize().to_vec())
}