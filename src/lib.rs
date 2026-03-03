// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2023-2026 Intel Corporation.

#![cfg_attr(not(test), no_std)]
#![allow(dead_code)]
#![allow(unused_variables)]

extern crate alloc;

mod asm;
pub mod tdcall;
pub mod tdvmcall;
pub mod unaccepted_memory;
mod ve;

use core::sync::atomic::{
    AtomicBool, AtomicU64, AtomicU8,
    Ordering::{Acquire, Relaxed, Release},
};

use bitflags::bitflags;
use raw_cpuid::{native_cpuid::cpuid_count, CpuIdResult};
use tdcall::{InitError, TdCallError, TdgVpInfo};
use ve::{handle_io, handle_mmio};

pub use self::{
    tdcall::{accept_page, get_veinfo, TdgVeInfo, TdxVirtualExceptionType},
    tdvmcall::{cpuid, hlt, print, rdmsr, wrmsr, TDX_LOGGER},
};

#[derive(Debug)]
pub enum TopologyError {
    TdCall(TdCallError),
    NotConfigured,
}

#[derive(Debug)]
pub enum SeptVeError {
    TdCall(TdCallError),
    Misconfiguration,
}

#[derive(Debug)]
pub enum AcceptError {
    TdCall(TdCallError),
    InvalidAlignment,
}

pub type TdxGpa = usize;

pub static SHARED_MASK: AtomicU64 = AtomicU64::new(0);

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

/// Returns true if the system is identified as an Intel TDX guest during early boot.
///
/// This function is designed for use in environments like the EFI stub where
/// complex initialization is not yet possible. It uses an internal atomic cache
/// to ensure that the hardware CPUID check is performed only once.
pub fn is_tdx_guest_early() -> bool {
    match TdxEarlyState::from(TDX_EARLY_STATE.load(Acquire)) {
        TdxEarlyState::Enabled => true,
        TdxEarlyState::Disabled => false,
        _ => {
            let is_tdx = is_tdx_hardware_present();
            let new_state = if is_tdx {
                TdxEarlyState::Enabled
            } else {
                TdxEarlyState::Disabled
            };

            TDX_EARLY_STATE.store(new_state as u8, Release);
            is_tdx
        }
    }
}

/// Performs full initialization of the Intel TDX guest environment.
///
/// This function validates the TDX hardware signature, invokes the `TDG.VP.INFO`
/// TDCALL to retrieve Trust Domain environment information, and configures global
/// state such as the shared memory mask.
pub fn init_tdx() -> Result<TdgVpInfo, InitError> {
    if tdx_is_enabled() {
        return tdcall::get_tdinfo().map_err(InitError::TdxGetVpInfoError);
    }

    check_tdx_guest()?;

    let info = tdcall::get_tdinfo().map_err(InitError::TdxGetVpInfoError)?;

    let gpaw: u64 = info.gpaw.into();
    let mask = 1u64 << (gpaw - 1);
    SHARED_MASK.store(mask, Relaxed);

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
            trapframe.set_rax((msr as u32) as usize);
            trapframe.set_rdx(((msr >> 32) as u32) as usize);
        }
        TdxVirtualExceptionType::MsrWrite => {
            let data = trapframe.rax() as u64 | ((trapframe.rdx() as u64) << 32);
            unsafe { wrmsr(trapframe.rcx() as u32, data).unwrap() };
        }
        TdxVirtualExceptionType::CpuId => {
            let cpuid_info = cpuid(trapframe.rax() as u32, trapframe.rcx() as u32).unwrap();
            let mask = 0xFFFF_FFFF_0000_0000_usize;
            trapframe.set_rax((trapframe.rax() & mask) | cpuid_info.eax);
            trapframe.set_rbx((trapframe.rbx() & mask) | cpuid_info.ebx);
            trapframe.set_rcx((trapframe.rcx() & mask) | cpuid_info.ecx);
            trapframe.set_rdx((trapframe.rdx() & mask) | cpuid_info.edx);
        }
        TdxVirtualExceptionType::EptViolation => {
            if is_protected_gpa(ve_info.guest_physical_address as TdxGpa) {
                serial_println!("Unexpected EPT-violation on private memory");
                hlt();
            }
            instr_len = handle_mmio(trapframe, ve_info).unwrap() as u32;
        }
        TdxVirtualExceptionType::Other => {
            serial_println!("Unknown TDX virtual exception type");
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

/// Accepts a range of physical memory to be used as TDX private memory.
///
/// # Safety
///
/// The caller must ensure the following invariants are met:
/// - **Address Validity**: The GPA range `[gpa_start, gpa_end)` must represent a valid range.
/// - **State Invariant**: The target memory pages must be in the `Pending` state.
///   Accepting pages that are already `Accepted` or in an uninitialized state will
///   result in a TDX instruction error.
/// - **Exclusive Access**: The caller must ensure no other CPU context is
///   simultaneously attempting to accept or access this specific GPA range to
///   prevent race conditions in the TDX Module's metadata.
/// - **Alignment**: While the function checks basic 4K alignment, the caller must ensure
///   the range corresponds to actual physical backing store provided by the VMM.
pub unsafe fn accept_memory(gpa_start: u64, gpa_end: u64) -> Result<(), AcceptError> {
    if gpa_start >= gpa_end {
        return Ok(());
    }

    if (gpa_start & (PageLevel::L1_4K.bytes() - 1)) != 0 {
        return Err(AcceptError::InvalidAlignment);
    }

    let mut current_addr = gpa_start;

    while current_addr < gpa_end {
        let len = gpa_end - current_addr;
        let mut accepted = false;

        for &level in &PageLevel::PRIORITIES {
            match try_accept_one(current_addr, len, level)? {
                TryAcceptResult::Accepted(size) => {
                    current_addr += size;
                    accepted = true;
                    break;
                }
                TryAcceptResult::SizeMismatch | TryAcceptResult::SkipLevel => {
                    // Try next (smaller) page level
                    continue;
                }
            }
        }

        if !accepted {
            // Fails if even L1_4K cannot be accepted
            return Err(AcceptError::InvalidAlignment);
        }
    }
    Ok(())
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

pub(crate) fn is_protected_gpa(gpa: TdxGpa) -> bool {
    let mask = SHARED_MASK.load(Relaxed);
    let gpa_u64 = u64::try_from(gpa).expect("TdxGpa must fit into u64 on x86_64");
    (gpa_u64 & mask) == 0
}

fn check_tdx_guest() -> Result<(), InitError> {
    let max_leaf = cpuid_count(0, 0).eax;
    if max_leaf < TDX_CPUID_LEAF_ID {
        return Err(InitError::TdxCpuLeafIdTooLow);
    }
    if !is_tdx_hardware_present() {
        return Err(InitError::TdxVendorIdMismatch);
    }

    Ok(())
}

fn is_tdx_hardware_present() -> bool {
    let res: CpuIdResult = cpuid_count(TDX_CPUID_LEAF_ID, 0);

    let mut sig = [0u8; 12];
    sig[0..4].copy_from_slice(&res.ebx.to_le_bytes());
    sig[4..8].copy_from_slice(&res.edx.to_le_bytes());
    sig[8..12].copy_from_slice(&res.ecx.to_le_bytes());

    &sig == TDX_IDENT
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum TdxEarlyState {
    Uninitialized = 0,
    Enabled = 1,
    Disabled = 2,
}

impl TdxEarlyState {
    const fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Enabled,
            2 => Self::Disabled,
            _ => Self::Uninitialized,
        }
    }
}

impl From<u8> for TdxEarlyState {
    fn from(value: u8) -> Self {
        Self::from_u8(value)
    }
}

static TDX_EARLY_STATE: AtomicU8 = AtomicU8::new(TdxEarlyState::Uninitialized as u8);
static TDX_ENABLED: AtomicBool = AtomicBool::new(false);

const TDX_IDENT: &[u8; 12] = b"IntelTDX    ";
const TDX_CPUID_LEAF_ID: u32 = 0x21;

/// Attempts to accept a single memory page at the specified level.
fn try_accept_one(
    start: u64,
    len: u64,
    page_level: PageLevel,
) -> Result<TryAcceptResult, AcceptError> {
    let size = page_level.bytes();

    if (start & (size - 1)) != 0 || len < size {
        return Ok(TryAcceptResult::SkipLevel);
    }

    match unsafe { accept_page(page_level as u64, start) } {
        Ok(_) => Ok(TryAcceptResult::Accepted(size)),
        Err(e) => match e {
            // PageSizeMismatch: VMM mapped it differently.
            // OperandInvalid: Hardware doesn't support this size or address is rejected.
            TdCallError::TdxPageSizeMismatch | TdCallError::TdxOperandInvalid => {
                if page_level == PageLevel::L1_4K {
                    // If the minimum architectural unit is rejected, it's a fatal error.
                    Err(AcceptError::TdCall(e))
                } else {
                    // Fall back to a smaller page size.
                    Ok(TryAcceptResult::SizeMismatch)
                }
            }
            _ => Err(AcceptError::TdCall(e)),
        },
    }
}

bitflags! {
    struct ConfigFlags: u64 {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum PageLevel {
    L1_4K = 0,
    L2_2M = 1,
    L3_1G = 2,
}

impl PageLevel {
    pub const PRIORITIES: [Self; 3] = [Self::L3_1G, Self::L2_2M, Self::L1_4K];

    pub const fn bytes(self) -> u64 {
        1 << (12 + (self as u32) * 9)
    }
}

/// Represents the result of a single page acceptance attempt.
enum TryAcceptResult {
    /// Successfully accepted a page of the given size.
    Accepted(u64),
    /// Current address or length is not aligned/sufficient for this level.
    SkipLevel,
    /// Hardware/VMM reports a size mismatch or lack of support for this level.
    SizeMismatch,
}

impl From<TdCallError> for TopologyError {
    fn from(err: TdCallError) -> Self {
        TopologyError::TdCall(err)
    }
}

impl From<TdCallError> for SeptVeError {
    fn from(err: TdCallError) -> Self {
        SeptVeError::TdCall(err)
    }
}

impl From<TdCallError> for AcceptError {
    fn from(err: TdCallError) -> Self {
        AcceptError::TdCall(err)
    }
}
