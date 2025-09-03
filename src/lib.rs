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

pub(crate) fn is_protected_gpa(gpa: TdxGpa) -> bool {
    (gpa as u64 & SHARED_MASK) == 0
}
