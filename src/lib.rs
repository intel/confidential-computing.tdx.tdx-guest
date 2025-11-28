// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2023-2024 Intel Corporation.

#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

mod asm;
pub mod tdcall;
pub mod tdvmcall;
mod ve;

use core::sync::atomic::{AtomicBool, Ordering::Relaxed};

use bitflags::bitflags;
use raw_cpuid::{native_cpuid::cpuid_count, CpuIdResult};
use tdcall::{InitError, TdgVpInfo};
use ve::{handle_io, handle_mmio};

pub use self::{
    tdcall::{get_veinfo, TdgVeInfo, TdxVirtualExceptionType},
    tdvmcall::{cpuid, hlt, print, rdmsr, wrmsr},
};

pub const SHARED_BIT: u8 = 51;
pub const SHARED_MASK: u64 = 1u64 << SHARED_BIT;

static TDX_ENABLED: AtomicBool = AtomicBool::new(false);

pub type TdxGpa = usize;

pub trait TdxTrapFrame {
    fn rax(&self) -> usize;
    fn set_rax(&mut self, rax: usize);
    fn rbx(&self) -> usize;
    fn set_rbx(&mut self, rbx: usize);
    fn rcx(&self) -> usize;
    fn set_rcx(&mut self, rcx: usize);
    fn rdx(&self) -> usize;
    fn set_rdx(&mut self, rdx: usize);
    fn rsi(&self) -> usize;
    fn set_rsi(&mut self, rsi: usize);
    fn rdi(&self) -> usize;
    fn set_rdi(&mut self, rdi: usize);
    fn rip(&self) -> usize;
    fn set_rip(&mut self, rip: usize);
    fn r8(&self) -> usize;
    fn set_r8(&mut self, r8: usize);
    fn r9(&self) -> usize;
    fn set_r9(&mut self, r9: usize);
    fn r10(&self) -> usize;
    fn set_r10(&mut self, r10: usize);
    fn r11(&self) -> usize;
    fn set_r11(&mut self, r11: usize);
    fn r12(&self) -> usize;
    fn set_r12(&mut self, r12: usize);
    fn r13(&self) -> usize;
    fn set_r13(&mut self, r13: usize);
    fn r14(&self) -> usize;
    fn set_r14(&mut self, r14: usize);
    fn r15(&self) -> usize;
    fn set_r15(&mut self, r15: usize);
    fn rbp(&self) -> usize;
    fn set_rbp(&mut self, rbp: usize);
}

#[inline(always)]
pub fn tdx_is_enabled() -> bool {
    TDX_ENABLED.load(Relaxed)
}

pub fn init_tdx() -> Result<TdgVpInfo, InitError> {
    check_tdx_guest()?;
    let info = tdcall::get_tdinfo()?;
    TDX_ENABLED.store(true, Relaxed);
    Ok(info)
}

pub fn handle_virtual_exception(trapframe: &mut dyn TdxTrapFrame, ve_info: &TdgVeInfo) {
    let mut instr_len = ve_info.exit_instruction_length;
    match ve_info.exit_reason.into() {
        TdxVirtualExceptionType::Hlt => {
            hlt();
        }
        TdxVirtualExceptionType::Io => {
            if !handle_io(trapframe, ve_info) {
                serial_println!("Handle tdx ioexit errors, ready to halt");
                hlt();
            }
        }
        TdxVirtualExceptionType::MsrRead => {
            let msr = unsafe { rdmsr(trapframe.rcx() as u32).unwrap() };
            trapframe.set_rax((msr as u32 & u32::MAX) as usize);
            trapframe.set_rdx(((msr >> 32) as u32 & u32::MAX) as usize);
        }
        TdxVirtualExceptionType::MsrWrite => {
            let data = trapframe.rax() as u64 | ((trapframe.rdx() as u64) << 32);
            unsafe { wrmsr(trapframe.rcx() as u32, data).unwrap() };
        }
        TdxVirtualExceptionType::CpuId => {
            let leaf = trapframe.rax() as u32;

            if leaf >= 0x40000000 && leaf <= 0x400000FF {
                let cpuid_info = cpuid(leaf, trapframe.rcx() as u32).unwrap();
                let mask = 0xFFFF_FFFF_0000_0000_usize;
                trapframe.set_rax((trapframe.rax() & mask) | cpuid_info.eax);
                trapframe.set_rbx((trapframe.rbx() & mask) | cpuid_info.ebx);
                trapframe.set_rcx((trapframe.rcx() & mask) | cpuid_info.ecx);
                trapframe.set_rdx((trapframe.rdx() & mask) | cpuid_info.edx);
            } else {
                    let mask = 0xFFFF_FFFF_0000_0000_usize;
                    trapframe.set_rax(trapframe.rax() & mask);
                    trapframe.set_rbx(trapframe.rbx() & mask);
                    trapframe.set_rcx(trapframe.rcx() & mask);
                    trapframe.set_rdx(trapframe.rdx() & mask);
            }
        }
        TdxVirtualExceptionType::EptViolation => {
            if is_protected_gpa(ve_info.guest_physical_address as TdxGpa) {
                serial_println!("Unexpected EPT-violation on private memory");
                hlt();
            }
            instr_len = handle_mmio(trapframe, ve_info).unwrap() as u32;
        }
        TdxVirtualExceptionType::Other => {
            serial_println!("Unknown TDX vitrual exception type");
            hlt();
        }
        _ => return,
    }
    trapframe.set_rip(trapframe.rip() + instr_len as usize);
}

pub fn reduce_unnecessary_ve() -> Result<(), TopologyError> {
    if tdcall::write_td_metadata(
        metadata::TD_CTLS,
        metadata::TdCtls::REDUCE_VE.bits(),
        metadata::TdCtls::REDUCE_VE.bits(),
    )
    .is_ok()
    {
        return Ok(());
    }

    enable_cpu_topology_enumeration()
}

pub fn enable_cpu_topology_enumeration() -> Result<(), TopologyError> {
    let configured = tdcall::read_td_metadata(metadata::TOPOLOGY_ENUM_CONFIGURED)?;

    if configured == 0 {
        return Err(TopologyError::NotConfigured);
    }

    tdcall::write_td_metadata(
        metadata::TD_CTLS,
        metadata::TdCtls::ENUM_TOPOLOGY.bits(),
        metadata::TdCtls::ENUM_TOPOLOGY.bits(),
    )?;

    Ok(())
}

pub fn disable_sept_ve(td_attr: TdAttributes) -> Result<(), SeptVeError> {
    let debug = td_attr.contains(TdAttributes::DEBUG);

    let config = ConfigFlags::from_bits_truncate(tdcall::read_td_metadata(metadata::CONFIG_FLAGS)?);

    if !config.contains(ConfigFlags::FLEXIBLE_PENDING_VE) {
        if td_attr.contains(TdAttributes::SEPT_VE_DISABLE) {
            return Ok(());
        }

        if !debug {
            return Err(SeptVeError::Misconfiguration);
        }
        return Ok(());
    }

    let controls =
        metadata::TdCtls::from_bits_truncate(tdcall::read_td_metadata(metadata::TD_CTLS)?);

    if controls.contains(metadata::TdCtls::PENDING_VE_DISABLE) {
        return Ok(());
    }

    if debug {
        return Ok(());
    }

    tdcall::write_td_metadata(
        metadata::TD_CTLS,
        metadata::TdCtls::PENDING_VE_DISABLE.bits(),
        metadata::TdCtls::PENDING_VE_DISABLE.bits(),
    )?;

    Ok(())
}

pub(crate) fn is_protected_gpa(gpa: TdxGpa) -> bool {
    (gpa as u64 & SHARED_MASK) == 0
}

fn check_tdx_guest() -> Result<(), InitError> {
    const TDX_CPUID_LEAF_ID: u64 = 0x21;
    let cpuid_leaf = cpuid_count(0, 0).eax as u64;
    if cpuid_leaf < TDX_CPUID_LEAF_ID {
        return Err(InitError::TdxCpuLeafIdError);
    }
    let cpuid_result: CpuIdResult = cpuid_count(TDX_CPUID_LEAF_ID as u32, 0);
    if &cpuid_result.ebx.to_ne_bytes() != b"Inte"
        || &cpuid_result.edx.to_ne_bytes() != b"lTDX"
        || &cpuid_result.ecx.to_ne_bytes() != b"    "
    {
        return Err(InitError::TdxVendorIdError);
    }
    Ok(())
}

pub mod metadata {
    /// Non-attested TD configuration flags.
    pub const CONFIG_FLAGS: u64 = 0x1110000300000016;
    /// A bitmap of TD controls that may be modified during TD run time.
    pub const TD_CTLS: u64 = 0x1110000300000017;
    /// Enable guest notification of events.
    pub const NOTIFY_ENABLES: u64 = 0x9100000000000010;
    /// Indicates whether virtual topology enumeration has been successfully configured.
    pub const TOPOLOGY_ENUM_CONFIGURED: u64 = 0x9100000000000019;

    use crate::bitflags;
    bitflags! {
        /// TD Control flags
        pub struct TdCtls: u64 {
            /// Controls the way guest TD access to a PENDING page is processed.
            const PENDING_VE_DISABLE = 1 << 0;
            /// Controls the enumeration of virtual platform topology.
            const ENUM_TOPOLOGY = 1 << 1;
            /// Controls the virtualization of CPUID(2).
            const VIRT_CPUID2 = 1 << 2;
            /// Allows the guest TD to control the way #VE is injected by the TDX module
            /// on guest TD execution of CPUID, RDMSR/WRMSR and other instructions.
            const REDUCE_VE = 1 << 3;
            /// Controls whether a migratable TD can request a sealing key using TDG.MR.KEY.GET.
            const FORCE_HW_KEYS = 1 << 4;
            /// Controls locking of TD-writable virtualization controls.
            const LOCK = 1 << 63;
        }
    }
}

bitflags! {
    pub struct ConfigFlags: u64 {
        /// GPAW (Guest Physical Address Width) controls the position of the SHARED bit in GPA.
        /// It is copied to each TD VMCS and L2 VMCS GPAW execution control on TDH.VP.INIT and TDH.IMPORT.STATE.VP.
        const GPAW = 1 << 0;
        /// Controls the guest TD’s ability to change the PENDING page access behavior from its default value.
        const FLEXIBLE_PENDING_VE = 1 << 1;
        /// Controls whether RBP value can be modified by TDG.VP.VMCALL and TDH.VP.ENTER.
        const NO_RBP_MOD = 1 << 2;
        /// Controls virtualization of physical address width, as enumerated by CPUID(0x80000008).EAX[7:0].
        const MAXPA_VIRT = 1 << 3;
        /// Controls virtualization of guest physical address width, as enumerated by CPUID(0x80000008).EAX[23:16].
        const MAXGPA_VIRT = 1 << 4;
        /// Enables TDX Connect for the current TD.
        const TDX_CONNECT = 1 << 5;
        /// Enables TDG.MEM.PAGE.RELEASE for the current TD.
        const PAGE_RELEASE = 1 << 6;
    }
}

bitflags! {
    /// TdAttributes is defined as a 64b field that specifies various attested guest TD attributes.
    pub struct TdAttributes: u64 {
        /// Guest TD runs in off-TD debug mode. Its VCPU state and private memory are accessible by the host VMM.
        /// DEBUG may not be set if MIGRATABLE is set.
        const DEBUG = 1 << 0;
        /// The TD is subject to HGS+ operation. HGS+ monitors the TD operation as part of the whole system.
        /// This bit may be set, if supported by the TDX module, regardless of CPU support.
        const HGS_PLUS_PROF = 1 << 4;
        /// The TD is subject to system profiling using performance monitoring counters.
        /// Those counters are not context-switched on TD entry and exit; they monitor the TD operation as part of the whole system.
        /// This bit may be set, if supported by the TDX module, regardless of CPU support.
        const PERF_PROF = 1 << 5;
        /// The TD is subject to system profiling using core out-of-band telemetry.
        /// Core telemetry monitors the TD operation as part of the whole system.
        /// This bit may be set, if supported by the TDX module, regardless of CPU support.
        const PMT_PROF = 1 << 6;
        /// Indicates that the TDX module must use Instruction-Count based Single-Step Defense to protect against single-step attacks.
        /// ICSSD may not be set if PERFMON is set.
        /// This bit may only be set if the TDX module supports ICSSD.
        const ICSSD = 1 << 16;
        /// TD is allowed to use Linear Address Space Separation.
        /// This bit may only be set if both the TDX module and the CPU support LASS.
        const LASS = 1 << 27;
        /// Disable EPT violation conversion to #VE(PENDING) on guest TD access of PENDING pages.
        const SEPT_VE_DISABLE = 1 << 28;
        /// TD is migratable (using a Migration TD).
        /// MIGRATABLE may not be set if either DEBUG or PERFMON is set.
        /// MIGRATABLE may not be set if CONFIG_FLAGS.TDX_CONNECT is set.
        /// This bit may only be set if the TDX module supports TD Migration.
        const MIGRATABLE = 1 << 29;
        /// TD is allowed to use Supervisor Protection Keys.
        /// This bit may only be set if both the TDX module and the CPU support PKS.
        const PKS = 1 << 30;
        /// TD is allowed to use Key Locker.
        /// This bit may only be set if both the TDX module and the CPU support Key Locker.
        const KL = 1 << 31;
        /// The TD is a TDX Connect Provisioning Agent. This bit may only be set if both the TDX module and the CPU support TDX Connect.
        const TPA = 1 << 62;
        /// TD is allowed to use Perfmon and PERF_METRICS capabilities.
        /// PERFMON may not be set if either MIGRATABLE or ICSSD is set.
        /// This bit may only be set if the TDX Module supports Performance Monitoring virtualization.
        const PERFMON = 1 << 63;
    }
}

#[derive(Debug)]
pub enum TopologyError {
    TdCall(tdcall::TdCallError),
    NotConfigured,
}

impl From<tdcall::TdCallError> for TopologyError {
    fn from(err: tdcall::TdCallError) -> Self {
        TopologyError::TdCall(err)
    }
}

#[derive(Debug)]
pub enum SeptVeError {
    TdCall(tdcall::TdCallError),
    Misconfiguration,
}

impl From<tdcall::TdCallError> for SeptVeError {
    fn from(err: tdcall::TdCallError) -> Self {
        SeptVeError::TdCall(err)
    }
}
