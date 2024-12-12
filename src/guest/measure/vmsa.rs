// use bytemuck::{bytes_of, Pod, Zeroable};
// use libc::{c_uchar, c_uint, c_ulonglong, c_ushort};

// use crate::guest::measure::types::SevMode;
// use crate::guest::measure::vcpu_types::CpuType;

// const BSP_EIP: c_ulonglong = 0xfffffff0;

// /// VMCB Segment (struct vmcb_seg in the linux kernel)
// #[repr(C)]
// #[derive(Debug, Clone, Copy)]
// pub struct VmcbSeg {
//     selector: c_ushort,
//     attrib: c_ushort,
//     limit: c_uint,
//     base: c_ulonglong,
// }

// impl VmcbSeg {
//     pub fn new(selector: c_ushort,
//                attrib: c_ushort,
//                limit: c_uint,
//                base: c_ulonglong) -> Self {
//         Self { selector, attrib, limit, base }
//     }
// }

// unsafe impl Zeroable for VmcbSeg {}

// unsafe impl Pod for VmcbSeg {}

// /// VMSA page
// ///
// /// The names of the fields are taken from struct sev_es_work_area in the linux kernel:
// /// https://github.com/AMDESE/linux/blob/sev-snp-v12/arch/x86/include/asm/svm.h#L318
// /// (following the definitions in AMD APM Vol 2 Table B-4)
// #[repr(C)]
// #[derive(Debug, Clone, Copy)]
// pub struct SevEsSaveArea {
//     es: VmcbSeg,
//     cs: VmcbSeg,
//     ss: VmcbSeg,
//     ds: VmcbSeg,
//     fs: VmcbSeg,
//     gs: VmcbSeg,
//     gdtr: VmcbSeg,
//     ldtr: VmcbSeg,
//     idtr: VmcbSeg,
//     tr: VmcbSeg,
//     vmpl0_ssp: c_ulonglong,
//     vmpl1_ssp: c_ulonglong,
//     vmpl2_ssp: c_ulonglong,
//     vmpl3_ssp: c_ulonglong,
//     u_cet: c_ulonglong,
//     reserved_1: [c_uchar; 2],
//     vmpl: c_uchar,
//     cpl: c_uchar,
//     reserved_2: [c_uchar; 4],
//     efer: c_ulonglong,
//     reserved_3: [c_uchar; 104],
//     xss: c_ulonglong,
//     cr4: c_ulonglong,
//     cr3: c_ulonglong,
//     cr0: c_ulonglong,
//     dr7: c_ulonglong,
//     dr6: c_ulonglong,
//     rflags: c_ulonglong,
//     rip: c_ulonglong,
//     dr0: c_ulonglong,
//     dr1: c_ulonglong,
//     dr2: c_ulonglong,
//     dr3: c_ulonglong,
//     dr0_addr_mask: c_ulonglong,
//     dr1_addr_mask: c_ulonglong,
//     dr2_addr_mask: c_ulonglong,
//     dr3_addr_mask: c_ulonglong,
//     reserved_4: [c_uchar; 24],
//     rsp: c_ulonglong,
//     s_cet: c_ulonglong,
//     ssp: c_ulonglong,
//     isst_addr: c_ulonglong,
//     rax: c_ulonglong,
//     star: c_ulonglong,
//     lstar: c_ulonglong,
//     cstar: c_ulonglong,
//     sfmask: c_ulonglong,
//     kernel_gs_base: c_ulonglong,
//     sysenter_cs: c_ulonglong,
//     sysenter_esp: c_ulonglong,
//     sysenter_eip: c_ulonglong,
//     cr2: c_ulonglong,
//     reserved_5: [c_uchar; 32],
//     g_pat: c_ulonglong,
//     dbgctrl: c_ulonglong,
//     br_from: c_ulonglong,
//     br_to: c_ulonglong,
//     last_excp_from: c_ulonglong,
//     last_excp_to: c_ulonglong,
//     reserved_6: [c_uchar; 80],
//     pkru: c_uint,
//     tsc_aux: c_uint,
//     reserved_7: [c_uchar; 24],
//     rcx: c_ulonglong,
//     rdx: c_ulonglong,
//     rbx: c_ulonglong,
//     reserved_8: c_ulonglong,
//     rbp: c_ulonglong,
//     rsi: c_ulonglong,
//     rdi: c_ulonglong,
//     r8: c_ulonglong,
//     r9: c_ulonglong,
//     r10: c_ulonglong,
//     r11: c_ulonglong,
//     r12: c_ulonglong,
//     r13: c_ulonglong,
//     r14: c_ulonglong,
//     r15: c_ulonglong,
//     reserved_9: [c_uchar; 16],
//     guest_exit_info_1: c_ulonglong,
//     guest_exit_info_2: c_ulonglong,
//     guest_exit_int_info: c_ulonglong,
//     guest_nrip: c_ulonglong,
//     sev_features: c_ulonglong,
//     vintr_ctrl: c_ulonglong,
//     guest_exit_code: c_ulonglong,
//     virtual_tom: c_ulonglong,
//     tlb_id: c_ulonglong,
//     pcpu_id: c_ulonglong,
//     event_inj: c_ulonglong,
//     xcr0: c_ulonglong,
//     reserved_10: [c_uchar; 16],
//     x87_dp: c_ulonglong,
//     mxcsr: c_uint,
//     x87_ftw: c_ushort,
//     x87_fsw: c_ushort,
//     x87_fcw: c_ushort,
//     x87_fop: c_ushort,
//     x87_ds: c_ushort,
//     x87_cs: c_ushort,
//     x87_rip: c_ulonglong,
//     fpreg_x87: [c_uchar; 80],
//     fpreg_xmm: [c_uchar; 256],
//     fpreg_ymm: [c_uchar; 256],
//     manual_padding: [c_uchar; 2448],
// }

// unsafe impl Zeroable for SevEsSaveArea {}

// unsafe impl Pod for SevEsSaveArea {}

// pub struct VMSA {
//     bsp_save_area: SevEsSaveArea,
//     ap_save_area: Option<SevEsSaveArea>,
// }

// impl VMSA {
//     pub fn new(sev_mode: SevMode, ap_eip: u64, vcpu_type: CpuType) -> Self {
//         let sev_features = match sev_mode {
//             SevMode::SevSnp => 0x1,
//             _ => 0x0
//         };

//         let mut us = Self {
//             bsp_save_area: Self::build_save_area(BSP_EIP,
//                                                  sev_features, vcpu_type.clone()),
//             ap_save_area: None,
//         };

//         if ap_eip > 0 {
//             us.ap_save_area = Some(Self::build_save_area(ap_eip as c_ulonglong,
//                                                          sev_features, vcpu_type));
//         }

//         us
//     }

//     pub(crate) fn build_save_area(eip: c_ulonglong,
//                                   sev_features: c_ulonglong,
//                                   vcpu_type: CpuType) -> SevEsSaveArea {
//         let mut area = SevEsSaveArea::zeroed();
//         area.es = VmcbSeg::new(0, 0x93, 0xffff, 0);
//         area.es = VmcbSeg::new(0, 0x93, 0xffff, 0);
//         area.cs = VmcbSeg::new(0xf000, 0x9b, 0xffff, eip & 0xffff0000);
//         area.ss = VmcbSeg::new(0, 0x93, 0xffff, 0);
//         area.ds = VmcbSeg::new(0, 0x93, 0xffff, 0);
//         area.fs = VmcbSeg::new(0, 0x93, 0xffff, 0);
//         area.gs = VmcbSeg::new(0, 0x93, 0xffff, 0);
//         area.gdtr = VmcbSeg::new(0, 0, 0xffff, 0);
//         area.idtr = VmcbSeg::new(0, 0, 0xffff, 0);
//         area.ldtr = VmcbSeg::new(0, 0x82, 0xffff, 0);
//         area.tr = VmcbSeg::new(0, 0x8b, 0xffff, 0);
//         area.efer = 0x1000;  // KVM enables EFER_SVME
//         area.cr4 = 0x40;     // KVM enables X86_CR4_MCE
//         area.cr0 = 0x10;
//         area.dr7 = 0x400;
//         area.dr6 = 0xffff0ff0;
//         area.rflags = 0x2;
//         area.rip = eip & 0xffff;
//         area.g_pat = 0x7040600070406;
//         area.rdx = vcpu_type.sig() as c_ulonglong;
//         area.sev_features = sev_features;
//         area.xcr0 = 0x1;
//         area.mxcsr = 0x1f80;
//         area.x87_fcw = 0x37f;

//         area
//     }

//     pub fn pages(&self, vcpus: usize) -> Vec<Vec<u8>> {
//         let bsp_save_area_bytes = bytes_of(&self.bsp_save_area);
//         let ap_save_area_bytes_maybe = self.ap_save_area
//             .map(|v| bytes_of(&v).to_vec());

//         let mut pages: Vec<Vec<u8>> = Vec::new();

//         for i in 0..vcpus {
//             if i == 0 {
//                 pages.push(bsp_save_area_bytes.to_vec());
//             } else {
//                 if let Some(v) = ap_save_area_bytes_maybe.as_ref() {
//                     pages.push(v.clone());
//                 }
//             }
//         }

//         pages
//     }
// }

// #[cfg(test)]
// mod tests {
//     use std::path::PathBuf;

//     use libc::c_ulonglong;

//     use crate::common::binary::fmt_bin_vec_to_hex;
//     use crate::guest::measure::ovmf::OVMF;
//     use crate::guest::measure::types::SevMode;
//     use crate::guest::measure::vcpu_types::CpuType;
//     use crate::guest::measure::vmsa::VMSA;

//     const RESOURCES_TEST_DIR: &str = "resources/test/measure";

//     #[test]
//     fn vmsa_test() {
//         let test_file = get_test_path("OVMF_CODE.fd");

//         let ovmf = OVMF::from_path(&test_file)
//             .expect("failed to load OVMF file");

//         let sev_es_reset_eip = ovmf.sev_es_reset_eip().unwrap();

//         let vmsa = VMSA::new(SevMode::SevSnp,
//                              sev_es_reset_eip as c_ulonglong, CpuType::EpycV4);
//         let pages = vmsa.pages(8);

//         assert_eq!(pages.len(), 8);

//         let first_page = pages.get(0).unwrap();

//         assert_eq!(fmt_bin_vec_to_hex(first_page), "00009300ffff0000000000000000000000f09b00ffff00000000ffff0000000000009300ffff0000000000000000000000009300ffff0000000000000000000000009300ffff0000000000000000000000009300ffff0000000000000000000000000000ffff0000000000000000000000008200ffff0000000000000000000000000000ffff0000000000000000000000008b00ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000010000000000000000004000000000000f00fffff000000000200000000000000f0ff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060407000604070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120f80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");

//         for idx in 1..pages.len() {
//             let page = pages.get(idx).unwrap();
//             assert_eq!(fmt_bin_vec_to_hex(page), "00009300ffff0000000000000000000000f09b00ffff0000000080000000000000009300ffff0000000000000000000000009300ffff0000000000000000000000009300ffff0000000000000000000000009300ffff0000000000000000000000000000ffff0000000000000000000000008200ffff0000000000000000000000000000ffff0000000000000000000000008b00ffff000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000010000000000000000004000000000000f00fffff00000000020000000000000004b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060407000604070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000120f80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
//         }
//     }

//     // Util
//     fn get_test_path(path: &str) -> PathBuf {
//         let mut test_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//         test_path.push(RESOURCES_TEST_DIR);
//         test_path.push(path);
//         test_path
//     }
// }

// SPDX-License-Identifier: Apache-2.0

//! Types and abstractions regarding Virtual Machine Save Areas (VMSAs).

#![allow(dead_code)]

use super::*;

use codicon::*;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::{
    fs,
    io::{self, Read, Write},
    mem::{size_of, MaybeUninit},
    slice::{from_raw_parts, from_raw_parts_mut},
};
const ATTR_G_SHIFT: usize = 23;
const ATTR_B_SHIFT: usize = 22;
const ATTR_L_SHIFT: usize = 21;
const ATTR_AVL_SHIFT: usize = 20;
const ATTR_P_SHIFT: usize = 15;
const ATTR_DPL_SHIFT: usize = 13;
const ATTR_S_SHIFT: usize = 12;
const ATTR_TYPE_SHIFT: usize = 8;
const ATTR_A_SHIFT: usize = 8;
const ATTR_CS_SHIFT: usize = 11;
const ATTR_C_SHIFT: usize = 10;
const ATTR_R_SHIFT: usize = 9;
const ATTR_E_SHIFT: usize = 10;
const ATTR_W_SHIFT: usize = 9;

const ATTR_G_MASK: usize = 1 << ATTR_G_SHIFT;
const ATTR_B_MASK: usize = 1 << ATTR_B_SHIFT;
const ATTR_L_MASK: usize = 1 << ATTR_L_SHIFT;
const ATTR_AVL_MASK: usize = 1 << ATTR_AVL_SHIFT;
const ATTR_P_MASK: u16 = 1 << ATTR_P_SHIFT;
const ATTR_DPL_MASK: u16 = 1 << ATTR_DPL_SHIFT;
const ATTR_S_MASK: u16 = 1 << ATTR_S_SHIFT;
const ATTR_TYPE_MASK: u16 = 1 << ATTR_TYPE_SHIFT;
const ATTR_A_MASK: u16 = 1 << ATTR_A_SHIFT;
const ATTR_CS_MASK: u16 = 1 << ATTR_CS_SHIFT;
const ATTR_C_MASK: u16 = 1 << ATTR_C_SHIFT;
const ATTR_R_MASK: u16 = 1 << ATTR_R_SHIFT;
const ATTR_E_MASK: u16 = 1 << ATTR_E_SHIFT;
const ATTR_W_MASK: u16 = 1 << ATTR_W_SHIFT;

pub trait TypeLoad: Read {
    fn load<T: Sized + Copy>(&mut self) -> Result<T> {
        #[allow(clippy::uninit_assumed_init)]
        let mut t = unsafe { MaybeUninit::uninit().assume_init() };
        let p = &mut t as *mut T as *mut u8;
        let s = unsafe { from_raw_parts_mut(p, size_of::<T>()) };
        self.read_exact(s)?;
        Ok(t)
    }
}

pub trait TypeSave: Write {
    fn save<T: Sized + Copy>(&mut self, value: &T) -> Result<()> {
        let p = value as *const T as *const u8;
        let s = unsafe { from_raw_parts(p, size_of::<T>()) };
        self.write_all(s)
    }
}

impl<T: Read> TypeLoad for T {}
impl<T: Write> TypeSave for T {}

/// Virtual Machine Control Block
/// The layout of a VMCB struct is documented in Table B-1 of the
/// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
#[repr(C, packed)]
#[derive(Default, Serialize, Deserialize, Clone, Copy)]
pub struct VmcbSegment {
    /// Segment selector: documented in Figure 4-3 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    selector: u16,

    /// Segment attributes.
    attrib: u16,

    /// Segment limit: used in comparisons with pointer offsets to prevent
    /// segment limit violations.
    limit: u32,

    /// Segment base address.
    base: u64,
}

/// Virtual Machine Save Area
/// The layout of a VMCB struct is documented in Table B-4 of the
/// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
#[repr(C, packed)]
#[derive(Copy, Clone, Serialize, Deserialize)]
pub struct Vmsa {
    /// Extra segment.
    es: VmcbSegment,

    /// Code segment.
    cs: VmcbSegment,

    /// Stack segment.
    ss: VmcbSegment,

    /// Data segment.
    ds: VmcbSegment,

    /// Segment with no specific use defined by the hardware.
    fs: VmcbSegment,

    /// Segment with no specific use defined by the hardware.
    gs: VmcbSegment,

    /// Base address of the Global Descriptor Table.
    gdtr: VmcbSegment,

    /// Base address of the Local Descriptor Table.
    ldtr: VmcbSegment,

    /// Base address of the Interrupt Descriptor Table.
    idtr: VmcbSegment,

    /// Points to a valid TSS segment descriptor which resides in the GDT.
    tr: VmcbSegment,

    /// Reserved.
    #[serde(with = "BigArray")]
    reserved_1: [u8; 43],

    /// Current privilege level.
    cpl: u8,

    /// Reserved.
    reserved_2: [u8; 4],

    /// Extended features enable register.
    efer: u64,

    /// Reserved.
    #[serde(with = "BigArray")]
    reserved_3: [u8; 104],

    /// Bitmap of supervisor-level state components. System software sets bits
    /// in the XSS register bitmap to enable management of corresponding state
    /// component by the XSAVES/XRSTORS instructions.
    xss: u64,

    /// Control register 4.
    cr4: u64,

    /// Control register 3.
    cr3: u64,

    /// Control register 0.
    cr0: u64,

    /// Debug register 7.
    dr7: u64,

    /// Debug register 6.
    dr6: u64,

    /// RFLAGS register. Documented in Figure 3-7 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    rflags: u64,

    /// Instruction pointer.
    rip: u64,

    /// Reserved.
    #[serde(with = "BigArray")]
    reserved_4: [u8; 88],

    /// Stack pointer.
    rsp: u64,

    /// Reserved.
    reserved_5: [u8; 24],

    /// RAX register.
    rax: u64,

    /// STAR register. Documented in Figure 6-1 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    star: u64,

    /// Target RIP of the called procedure in long mode when the calling
    /// software is in 64-bit mode.
    lstar: u64,

    /// Target RIP of the called procedure in long mode when the calling
    /// software is in compatibility mode.
    cstar: u64,

    /// Used in long mode to specify how rFLAGS is handled by SYSCALL
    /// instructions.
    sfmask: u64,

    /// This register is used by the SWAPGS instruction. This instruction
    /// exchanges the value located in KernelGSbase with the value located in
    /// "GS.base".
    kernel_gs_base: u64,

    /// CS linkage information for SYSENTER and SYSEXIT instructions.
    sysenter_cs: u64,

    /// ESP linkage information for SYSENTER and SYSEXIT instructions.
    sysenter_esp: u64,

    /// EIP linkage information for SYSENTER and SYSEXIT instructions.
    sysenter_eip: u64,

    /// Control register 2.
    cr2: u64,

    /// Reserved.
    reserved_6: [u8; 32],

    /// Register for holding guest PAT information.
    g_pat: u64,

    /// Holds the guest value of the DebugCTL MSR.
    dbgctl: u64,

    /// Holds the guest value of the LastBranchFromIP MSR.
    br_from: u64,

    /// Holds the guest value of the LastBranchToIP MSR.
    br_to: u64,

    /// Holds the guest value of the LastIntFromIP MSR.
    last_excp_from: u64,

    /// Holds the guest value of the LastIntToIPLastIntToIP MSR.
    last_excp_to: u64,

    /// Reserved.
    #[serde(with = "BigArray")]
    reserved_7: [u8; 72],

    /// Speculation Control of MSRs. Documented in Section 3.2.9 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    spec_ctrl: u32,

    /// Reserved.
    reserved_7b: [u8; 4],

    /// Memory Protection Key information. Documented in Section 5.6.7 of the
    /// AMD64 Architecture Programmer’s Manual, Volume 2: System Programming
    pkru: u32,

    /// Reserved.
    reserved_7a: [u8; 20],

    /// Reserved.
    reserved_8: u64,

    /// RCX register.
    rcx: u64,

    /// RDX register.
    rdx: u64,

    /// RBX register.
    rbx: u64,

    /// Reserved.
    reserved_9: u64,

    /// RBP register.
    rbp: u64,

    /// RSI register.
    rsi: u64,

    /// RDI register.
    rdi: u64,

    /// R8 register.
    r8: u64,

    /// R9 register.
    r9: u64,

    /// R10 register.
    r10: u64,

    /// R11 register.
    r11: u64,

    /// R12 register.
    r12: u64,

    /// R13 register.
    r13: u64,

    /// R14 register.
    r14: u64,

    /// R15 register.
    r15: u64,

    /// Reserved.
    reserved_10: [u8; 16],

    /// Exit code.
    sw_exit_code: u64,

    /// Values written to the vAPIC ICRH and ICRL registers.
    sw_exit_info_1: u64,

    /// Information describing the specific reason for the IPI delivery
    /// failure.
    sw_exit_info_2: u64,

    /// Scratch register.
    sw_scratch: u64,

    /// Reserved.
    #[serde(with = "BigArray")]
    reserved_11: [u8; 56],

    /// XCR0 register.
    xcr0: u64,

    /// Valid bitmap.
    valid_bitmap: [u8; 16],

    /// gPA of the x87 state.
    x87_state_gpa: u64,
}

impl Decoder<()> for Vmsa {
    type Error = crate::error::Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        Ok(reader.load()?)
    }
}

impl Encoder<()> for Vmsa {
    type Error = crate::error::Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> Result<()> {
        Ok(writer.save(self)?)
    }
}

impl Vmsa {
    /// Set VMSA values to follow initialization for an amd64 CPU.
    pub fn init_amd64(&mut self) {
        self.cr0 = 1 << 4;
        self.rip = 0xfff0;

        self.cs.selector = 0xf000;
        self.cs.base = 0xffff0000;
        self.cs.limit = 0xffff;

        self.ds.limit = 0xffff;

        self.es.limit = 0xffff;
        self.fs.limit = 0xffff;
        self.gs.limit = 0xffff;
        self.ss.limit = 0xffff;

        self.gdtr.limit = 0xffff;
        self.idtr.limit = 0xffff;

        self.ldtr.limit = 0xffff;
        self.tr.limit = 0xffff;

        self.dr6 = 0xffff0ff0;
        self.dr7 = 0x0400;
        self.rflags = 0x2;
        self.xcr0 = 0x1;
    }

    /// Set VMSA values to follow initialization for a VM running as a KVM guest.
    pub fn init_kvm(&mut self) {
        // svm_set_cr4() sets guest X86_CR4_MCE bit if host
        // has X86_CR4_MCE enabled
        self.cr4 = 0x40;

        // svm_set_efer sets guest EFER_SVME (Secure Virtual Machine enable)
        self.efer = 0x1000;

        // init_vmcb + init_sys_seg() sets
        // SVM_SELECTOR_P_MASK | SEG_TYPE_LDT
        self.ldtr.attrib = 0x0082;

        // init_vmcb + init_sys_seg() sets
        // SVM_SELECTOR_P_MASK | SEG_TYPE_BUSY_TSS16
        self.tr.attrib = 0x0083;

        // kvm_arch_vcpu_create() in arch/x86/kvm/x86.c
        self.g_pat = 0x0007040600070406;
    }

    // Based on logic in setup_regs() (src/arch/src/x86_64/regs.rs)
    /// Set VMSA values to follow initialization for a VM running as a krun guest.
    pub fn init_krun(&mut self, cpu: u64) {
        self.rsi = 0x7000;
        self.rbp = 0x8ff0;
        self.rsp = 0x8ff0;

        // Doesn't match with configure_segments_and_sregs
        self.cs.attrib =
            (ATTR_P_MASK | ATTR_S_MASK | ATTR_CS_MASK | ATTR_R_MASK) >> ATTR_TYPE_SHIFT;
        self.ds.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.es.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.ss.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK) >> ATTR_TYPE_SHIFT;
        self.fs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.gs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;

        if cpu > 0 {
            self.rip = 0;
            self.rsp = 0;
            self.rbp = 0;
            self.rsi = 0;

            self.cs.selector = 0x9100;
            self.cs.base = 0x91000;
        }
    }

    // Based on logic in x86_cpu_reset() (target/i386/cpu.c)
    /// Set VMSA values to follow initialization for a VM running as a QEMU guest.
    pub fn init_qemu(&mut self, _cpu: u64) {
        self.ldtr.attrib = (ATTR_P_MASK | (2 << ATTR_TYPE_SHIFT)) >> ATTR_TYPE_SHIFT;
        self.tr.attrib = (ATTR_P_MASK | (11 << ATTR_TYPE_SHIFT)) >> ATTR_TYPE_SHIFT;
        self.cs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_CS_MASK | ATTR_R_MASK | ATTR_A_MASK)
            >> ATTR_TYPE_SHIFT;
        self.ds.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.es.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.ss.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.fs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;
        self.gs.attrib = (ATTR_P_MASK | ATTR_S_MASK | ATTR_W_MASK | ATTR_A_MASK) >> ATTR_TYPE_SHIFT;

        self.g_pat = 0x0007040600070406;
    }

    /// Set CPU SKU values for a given VMSA.
    pub fn cpu_sku(&mut self, mut family: u64, mut model: u64, mut stepping: u64) {
        stepping &= 0xf;
        model &= 0xff;
        family &= 0xfff;

        self.rdx = stepping;

        if family > 0xf {
            self.rdx |= 0xf00 | ((family - 0x0f) << 20);
        } else {
            self.rdx |= family << 8;
        }

        self.rdx |= ((model & 0xf) << 4) | ((model >> 4) << 16);
    }

    /// Set VMSA reset address register values.
    pub fn reset_addr(&mut self, ra: u32) {
        let reset_cs = ra & 0xffff0000;
        let reset_ip = ra & 0x0000ffff;

        self.rip = u64::from(reset_ip);
        self.cs.base = u64::from(reset_cs);
    }

    // /// Read binary content from a passed filename and deserialize it into a
    // /// VMSA struct. Validate that the passed file is 4096 bytes long,
    // /// which is expected by SEV measurement validation.
    // pub fn from_file(filename: &str) -> Result<Self, std::io::Error> {
    //     let data = std::fs::read(filename)?;
    //     if data.len() != 4096 {
    //         return Err(std::io::Error::new(
    //             io::ErrorKind::InvalidData,
    //             format!("Expected VMSA length 4096, was {}", data.len()),
    //         ));
    //     }
    //     let vmsa = Vmsa::decode(&data[..], ())?;
    //     Ok(vmsa)
    // }

    /// Serialize a VMSA struct and write it to a passed filename,
    /// This ensures it is padded to 4096 bytes which is expected
    /// by SEV measurement validation.
    pub fn to_file(&self, filename: &str) -> Result<(), io::Error> {
        let mut vmsa_buf = Vec::new();
        self.encode(&mut vmsa_buf, ())?;

        const SIZE: usize = size_of::<Vmsa>();

        // Pad to 4096 bytes
        let buf: &mut [u8] = &mut [0; 4096];
        buf[..SIZE].copy_from_slice(&vmsa_buf[..]);

        fs::write(filename, buf)?;
        Ok(())
    }
}

impl Default for Vmsa {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}
