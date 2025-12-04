// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2023-2024 Intel Corporation.

//! The TDVMCALL helps invoke services from the host VMM. From the perspective of the host VMM, the TDVMCALL is a trap-like, VM exit into
//! the host VMM, reported via the SEAMRET instruction flow.
//!
//! By design, after the SEAMRET, the host VMM services the request specified in the parameters
//! passed by the TD during the TDG.VP.VMCALL (that are passed via SEAMRET to the VMM), then
//! resumes the TD via a SEAMCALL [TDH.VP.ENTER] invocation.
extern crate alloc;

use alloc::fmt;
use core::fmt::Write;
use x86_64::registers::rflags::{self, RFlags};
use crate::asm::asm_td_vmcall;

#[derive(Debug, PartialEq)]
pub enum TdVmcallError {
    /// TDCALL[TDG.VP.VMCALL] sub-function invocation must be retried.
    TdxRetry,
    /// Invalid operand to TDG.VP.VMCALL sub-function.
    TdxOperandInvalid,
    /// GPA already mapped.
    TdxGpaInuse,
    /// Operand (address) aligned error.
    TdxAlignError,
    Other,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct CpuIdInfo {
    pub eax: usize,
    pub ebx: usize,
    pub ecx: usize,
    pub edx: usize,
}

pub enum IoSize {
    Size1 = 1,
    Size2 = 2,
    Size4 = 4,
    Size8 = 8,
}

pub enum Direction {
    In,
    Out,
}

pub enum Operand {
    Dx,
    Immediate,
}

pub fn cpuid(eax: u32, ecx: u32) -> Result<CpuIdInfo, TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::Cpuid as u64,
        r12: eax as u64,
        r13: ecx as u64,
        ..Default::default()
    };
    td_vmcall(&mut args)?;
    Ok(CpuIdInfo {
        eax: args.r12 as usize,
        ebx: args.r13 as usize,
        ecx: args.r14 as usize,
        edx: args.r15 as usize,
    })
}

pub fn hlt() {
    let interrupt_blocked = !rflags::read().contains(RFlags::INTERRUPT_FLAG);
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::Hlt as u64,
        r12: interrupt_blocked as u64,
        ..Default::default()
    };
    let _ = td_vmcall(&mut args);
}

macro_rules! io_read {
    ($port:expr, $ty:ty) => {{
        let mut args = TdVmcallArgs {
            r11: TdVmcallNum::Io as u64,
            r12: core::mem::size_of::<$ty>() as u64,
            r13: IO_READ,
            r14: $port as u64,
            ..Default::default()
        };
        td_vmcall(&mut args)?;
        Ok(args.r11 as u32)
    }};
}

macro_rules! io_write {
    ($port:expr, $byte:expr, $size:expr) => {{
        let mut args = TdVmcallArgs {
            r11: TdVmcallNum::Io as u64,
            r12: core::mem::size_of_val(&$byte) as u64,
            r13: IO_WRITE,
            r14: $port as u64,
            r15: $byte as u64,
            ..Default::default()
        };
        td_vmcall(&mut args)
    }};
}

pub fn io_read(size: IoSize, port: u16) -> Result<u32, TdVmcallError> {
    match size {
        IoSize::Size1 => io_read!(port, u8),
        IoSize::Size2 => io_read!(port, u16),
        IoSize::Size4 => io_read!(port, u32),
        _ => unreachable!(),
    }
}

pub fn io_write(size: IoSize, port: u16, byte: u32) -> Result<(), TdVmcallError> {
    match size {
        IoSize::Size1 => io_write!(port, byte as u8, u8),
        IoSize::Size2 => io_write!(port, byte as u16, u16),
        IoSize::Size4 => io_write!(port, byte, u32),
        _ => unreachable!(),
    }
}

/// # Safety
/// Make sure the mmio address is valid.
pub unsafe fn read_mmio(size: IoSize, mmio_gpa: u64) -> Result<u64, TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::RequestMmio as u64,
        r12: size as u64,
        r13: 0,
        r14: mmio_gpa,
        ..Default::default()
    };
    td_vmcall(&mut args)?;
    Ok(args.r11)
}

/// # Safety
/// Make sure the mmio address is valid.
pub unsafe fn write_mmio(size: IoSize, mmio_gpa: u64, data: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::RequestMmio as u64,
        r12: size as u64,
        r13: 1,
        r14: mmio_gpa,
        r15: data,
        ..Default::default()
    };
    td_vmcall(&mut args)
}

/// MapGPA TDG.VP.VMCALL is used to help request the host VMM to map a GPA range as private
/// or shared-memory mappings. This API may also be used to convert page mappings from
/// private to shared. The GPA range passed in this operation can indicate if the mapping is
/// requested for a shared or private memory via the GPA.Shared bit in the start address.
pub fn map_gpa(gpa: u64, size: u64) -> Result<(), (u64, TdVmcallError)> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::Mapgpa as u64,
        r12: gpa,
        r13: size,
        ..Default::default()
    };
    td_vmcall(&mut args).map_err(|e| (args.r11, e))
}

/// # Safety
/// Make sure the index is valid.
pub unsafe fn rdmsr(index: u32) -> Result<u64, TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::Rdmsr as u64,
        r12: index as u64,
        ..Default::default()
    };
    td_vmcall(&mut args)?;
    Ok(args.r11)
}

/// # Safety
/// Make sure the index and the corresponding value are valid.
pub unsafe fn wrmsr(index: u32, value: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::Wrmsr as u64,
        r12: index as u64,
        r13: value,
        ..Default::default()
    };
    td_vmcall(&mut args)
}

/// Used to help perform WBINVD or WBNOINVD operation.
/// - cache_operation: 0: WBINVD, 1: WBNOINVD
pub fn perform_cache_operation(cache_operation: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::Wbinvd as u64,
        r12: cache_operation,
        ..Default::default()
    };
    td_vmcall(&mut args)
}

/// GetQuote TDG.VP.VMCALL is a doorbell-like interface used to help send a message to the
/// host VMM to queue operations that tend to be long-running operations.
///
/// GetQuote is designed to invoke a request to generate a TD-Quote signing by a service hosting TD-Quoting
/// Enclave operating in the host environment for a TD Report passed as a parameter by the TD.
///
/// TDREPORT_STRUCT is a memory operand intended to be sent via the GetQuote
/// TDG.VP.VMCALL to indicate the asynchronous service requested.
pub fn get_quote(shared_gpa: u64, size: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::GetQuote as u64,
        r12: shared_gpa,
        r13: size,
        ..Default::default()
    };
    td_vmcall(&mut args)
}

/// The guest TD may request that the host VMM specify which interrupt vector to use as an event-notify vector.
///
/// This is designed as an untrusted operation; thus, the TD OS should be designed not to use the event notification for trusted operations.
///
/// Example of an operation that can use the event notify is the host VMM signaling a device removal to the TD, in
/// response to which a TD may unload a device driver.
///
/// The host VMM should use SEAMCALL [TDWRVPS] leaf to inject an interrupt at the requestedinterrupt vector into the TD VCPU that executed TDG.VP.VMCALL
/// <SetupEventNotifyInterrupt> via the posted-interrupt descriptor.
pub fn setup_event_notify_interrupt(interrupt_vector: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::SetupEventNotifyInterrupt as u64,
        r12: interrupt_vector,
        ..Default::default()
    };
    td_vmcall(&mut args)
}

/// GetTdVmCallInfo TDG.VP.VMCALL is used to help request the host VMM enumerate which
/// TDG.VP.VMCALLs are supported.
pub fn get_tdvmcall_info(interrupt_vector: u64) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::GetTdVmcallInfo as u64,
        // This register is reserved to extend TDG.VP.VMCALL enumeration in future versions.
        r12: 0,
        ..Default::default()
    };
    td_vmcall(&mut args)
}

/// In Service TD scenario, there is a need to define interfaces for the command/response that
/// may have long latency, such as communicating with local device via Secure Protocol and Data
/// Model (SPDM), communicating with remote platform via Transport Layer Security (TLS)
/// Protocol, or communicating with a Quoting Enclave (QE) on attestation or mutual
/// authentication.
///
/// There is also needed that the VMM may notify a service TD to do some actions, such as
/// Migration TD (MigTD).
///
/// We define Command/Response Buffer (CRB) DMA interface.
///
/// Inputs:
/// - shared_gpa_input: Shared 4KB aligned GPA as input – the memory contains a Command.
///   It could be more than one 4K pages.
/// - shared_gpa_output: Shared 4KB aligned GPA as output – the memory contains a Response.
///   It could be more than one 4K pages.
/// - interrupt_vector: Event notification interrupt vector - (valid values 32~255) selected by TD.
///   0: blocking action. VMM need get response then return.
///   1~31: Reserved. Should not be used.
///   32~255: Non-block action. VMM can return immediately and signal the interrupt vector when the response is ready.
///   VMM should inject interrupt vector into the TD VCPU that executed TDG.VP.VMCALL<Service>.
/// - time_out: Timeout– Maximum wait time for the command and response. 0 means infinite wait.
pub fn get_td_service(
    shared_gpa_input: u64,
    shared_gpa_output: u64,
    interrupt_vector: u64,
    time_out: u64,
) -> Result<(), TdVmcallError> {
    let mut args = TdVmcallArgs {
        r11: TdVmcallNum::Service as u64,
        r12: shared_gpa_input,
        r13: shared_gpa_output,
        r14: interrupt_vector,
        r15: time_out,
        ..Default::default()
    };
    td_vmcall(&mut args)
}

pub fn print(args: fmt::Arguments) {
    Serial
        .write_fmt(args)
        .expect("Failed to write to serial port");
}

#[macro_export]
macro_rules! serial_print {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::tdvmcall::print(format_args!($fmt $(, $($arg)+)?));
    }
}

#[macro_export]
macro_rules! serial_println {
    ($fmt: literal $(, $($arg: tt)+)?) => {
        $crate::tdvmcall::print(format_args!(concat!($fmt, "\n") $(, $($arg)+)?))
    }
}

/// TDVMCALL Instruction Leaf Numbers Definition.
#[repr(u64)]
pub enum TdVmcallNum {
    Cpuid = 0x0000a,
    Hlt = 0x0000c,
    Io = 0x0001e,
    Rdmsr = 0x0001f,
    Wrmsr = 0x00020,
    RequestMmio = 0x00030,
    Wbinvd = 0x00036,
    GetTdVmcallInfo = 0x10000,
    Mapgpa = 0x10001,
    GetQuote = 0x10002,
    SetupEventNotifyInterrupt = 0x10004,
    Service = 0x10005,
}

#[repr(C)]
#[derive(Default)]
pub(crate) struct TdVmcallArgs {
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

const SERIAL_IO_PORT: u16 = 0x3F8;
const SERIAL_LINE_STS: u16 = 0x3FD;
const IO_READ: u64 = 0;
const IO_WRITE: u64 = 1;

fn td_vmcall(args: &mut TdVmcallArgs) -> Result<(), TdVmcallError> {
    let result = unsafe { asm_td_vmcall(args) };
    match result {
        0 => Ok(()),
        _ => Err(result.into()),
    }
}

struct Serial;

impl Write for Serial {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &byte in s.as_bytes() {
            io_write!(SERIAL_IO_PORT, byte, u8).unwrap();
        }
        Ok(())
    }
}

impl From<u64> for TdVmcallError {
    fn from(val: u64) -> Self {
        match val {
            0x1 => Self::TdxRetry,
            0x8000_0000_0000_0000 => Self::TdxOperandInvalid,
            0x8000_0000_0000_0001 => Self::TdxGpaInuse,
            0x8000_0000_0000_0002 => Self::TdxAlignError,
            _ => Self::Other,
        }
    }
}
