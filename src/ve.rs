// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2023-2024 Intel Corporation.

//! Virtualization Extensions (VE) module.
use iced_x86::{Code, Decoder, DecoderOptions, Instruction, Register};

use crate::{
    tdcall::TdgVeInfo,
    tdvmcall::{
        io_read, io_write, read_mmio, write_mmio, Direction, IoSize, Operand, TdVmcallError,
    },
    TdxTrapFrame,
};

#[derive(Debug)]
pub(crate) enum MmioError {
    Unimplemented,
    InvalidInstruction,
    InvalidAddress,
    DecodeFailed,
    TdVmcallError(TdVmcallError),
}

pub(crate) fn handle_io(trapframe: &mut dyn TdxTrapFrame, ve_info: &TdgVeInfo) -> bool {
    let size = match ve_info.exit_qualification & 0x3 {
        0 => IoSize::Size1,
        1 => IoSize::Size2,
        3 => IoSize::Size4,
        _ => panic!("Invalid size value"),
    };
    let direction = if (ve_info.exit_qualification >> 3) & 0x1 == 0 {
        Direction::Out
    } else {
        Direction::In
    };
    let operand = if (ve_info.exit_qualification >> 6) & 0x1 == 0 {
        Operand::Dx
    } else {
        Operand::Immediate
    };
    let port = (ve_info.exit_qualification >> 16) as u16;

    match direction {
        Direction::In => {
            trapframe.set_rax(io_read(size, port).unwrap() as usize);
        }
        Direction::Out => {
            io_write(size, port, trapframe.rax() as u32).unwrap();
        }
    };
    true
}

pub(crate) fn handle_mmio(
    trapframe: &mut dyn TdxTrapFrame,
    ve_info: &TdgVeInfo,
) -> Result<usize, MmioError> {
    // Get instruction
    let instr = decode_instr(trapframe.rip())?;

    // Decode MMIO instruction
    match decode_mmio(&instr) {
        Some((mmio, size)) => {
            match mmio {
                InstrMmioType::Write => {
                    let value = match instr.op1_register() {
                        Register::RAX => trapframe.rax() as u64,
                        Register::RBX => trapframe.rbx() as u64,
                        Register::RCX => trapframe.rcx() as u64,
                        Register::RDX => trapframe.rdx() as u64,
                        Register::R8 => trapframe.r8() as u64,
                        Register::R9 => trapframe.r9() as u64,
                        Register::R10 => trapframe.r10() as u64,
                        Register::R11 => trapframe.r11() as u64,
                        Register::R12 => trapframe.r12() as u64,
                        Register::R13 => trapframe.r13() as u64,
                        Register::R14 => trapframe.r14() as u64,
                        Register::R15 => trapframe.r15() as u64,
                        Register::RSI => trapframe.rsi() as u64,
                        Register::RDI => trapframe.rdi() as u64,
                        Register::RBP => trapframe.rbp() as u64,
                        Register::EAX => (trapframe.rax() & 0xFFFF_FFFF) as u64,
                        Register::EBX => (trapframe.rbx() & 0xFFFF_FFFF) as u64,
                        Register::ECX => (trapframe.rcx() & 0xFFFF_FFFF) as u64,
                        Register::EDX => (trapframe.rdx() & 0xFFFF_FFFF) as u64,
                        Register::R8D => (trapframe.r8() & 0xFFFF_FFFF) as u64,
                        Register::R9D => (trapframe.r9() & 0xFFFF_FFFF) as u64,
                        Register::R10D => (trapframe.r10() & 0xFFFF_FFFF) as u64,
                        Register::R11D => (trapframe.r11() & 0xFFFF_FFFF) as u64,
                        Register::R12D => (trapframe.r12() & 0xFFFF_FFFF) as u64,
                        Register::R13D => (trapframe.r13() & 0xFFFF_FFFF) as u64,
                        Register::R14D => (trapframe.r14() & 0xFFFF_FFFF) as u64,
                        Register::R15D => (trapframe.r15() & 0xFFFF_FFFF) as u64,
                        Register::ESI => (trapframe.rsi() & 0xFFFF_FFFF) as u64,
                        Register::EDI => (trapframe.rdi() & 0xFFFF_FFFF) as u64,
                        Register::EBP => (trapframe.rbp() & 0xFFFF_FFFF) as u64,
                        Register::AX => (trapframe.rax() & 0xFFFF) as u64,
                        Register::BX => (trapframe.rbx() & 0xFFFF) as u64,
                        Register::CX => (trapframe.rcx() & 0xFFFF) as u64,
                        Register::DX => (trapframe.rdx() & 0xFFFF) as u64,
                        Register::R8W => (trapframe.r8() & 0xFFFF) as u64,
                        Register::R9W => (trapframe.r9() & 0xFFFF) as u64,
                        Register::R10W => (trapframe.r10() & 0xFFFF) as u64,
                        Register::R11W => (trapframe.r11() & 0xFFFF) as u64,
                        Register::R12W => (trapframe.r12() & 0xFFFF) as u64,
                        Register::R13W => (trapframe.r13() & 0xFFFF) as u64,
                        Register::R14W => (trapframe.r14() & 0xFFFF) as u64,
                        Register::R15W => (trapframe.r15() & 0xFFFF) as u64,
                        Register::SI => (trapframe.rsi() & 0xFFFF) as u64,
                        Register::DI => (trapframe.rdi() & 0xFFFF) as u64,
                        Register::BP => (trapframe.rbp() & 0xFFFF) as u64,
                        Register::AL => (trapframe.rax() & 0xFF) as u64,
                        Register::BL => (trapframe.rbx() & 0xFF) as u64,
                        Register::CL => (trapframe.rcx() & 0xFF) as u64,
                        Register::DL => (trapframe.rdx() & 0xFF) as u64,
                        Register::R8L => (trapframe.r8() & 0xFF) as u64,
                        Register::R9L => (trapframe.r9() & 0xFF) as u64,
                        Register::R10L => (trapframe.r10() & 0xFF) as u64,
                        Register::R11L => (trapframe.r11() & 0xFF) as u64,
                        Register::R12L => (trapframe.r12() & 0xFF) as u64,
                        Register::R13L => (trapframe.r13() & 0xFF) as u64,
                        Register::R14L => (trapframe.r14() & 0xFF) as u64,
                        Register::R15L => (trapframe.r15() & 0xFF) as u64,
                        Register::SIL => (trapframe.rsi() & 0xFF) as u64,
                        Register::DIL => (trapframe.rdi() & 0xFF) as u64,
                        Register::BPL => (trapframe.rbp() & 0xFF) as u64,
                        _ => todo!(),
                    };
                    // Safety: The mmio_gpa obtained from `ve_info` is valid, and the value and size parsed from the instruction are valid.
                    unsafe {
                        write_mmio(size, ve_info.guest_physical_address, value)
                            .map_err(MmioError::TdVmcallError)?
                    }
                }
                InstrMmioType::WriteImm => {
                    // Retrieve the second operand of the instruction, which is the immediate value to be written.
                    // In x86 MOV instructions, when the destination is a memory location or a register, the immediate value is always the second operand.
                    let value = instr.immediate(1);
                    // Safety: The mmio_gpa obtained from `ve_info` is valid, and the value and size parsed from the instruction are valid.
                    unsafe {
                        write_mmio(size, ve_info.guest_physical_address, value)
                            .map_err(MmioError::TdVmcallError)?
                    }
                }
                InstrMmioType::Read =>
                // Safety: The mmio_gpa obtained from `ve_info` is valid, and the size parsed from the instruction is valid.
                unsafe {
                    let read_res = read_mmio(size, ve_info.guest_physical_address)
                        .map_err(MmioError::TdVmcallError)?
                        as usize;
                    // serial_println!("instr.op0_register: {:?}", instr.op0_register());
                    match instr.op0_register() {
                        Register::RAX => trapframe.set_rax(read_res),
                        Register::RBX => trapframe.set_rbx(read_res),
                        Register::RCX => trapframe.set_rcx(read_res),
                        Register::RDX => trapframe.set_rdx(read_res),
                        Register::R8 => trapframe.set_r8(read_res),
                        Register::R9 => trapframe.set_r9(read_res),
                        Register::R10 => trapframe.set_r10(read_res),
                        Register::R11 => trapframe.set_r11(read_res),
                        Register::R12 => trapframe.set_r12(read_res),
                        Register::R13 => trapframe.set_r13(read_res),
                        Register::R14 => trapframe.set_r14(read_res),
                        Register::R15 => trapframe.set_r15(read_res),
                        Register::RSI => trapframe.set_rsi(read_res),
                        Register::RDI => trapframe.set_rdi(read_res),
                        Register::RBP => trapframe.set_rbp(read_res),
                        Register::EAX => trapframe.set_rax(read_res),
                        Register::EBX => trapframe.set_rbx(read_res),
                        Register::ECX => trapframe.set_rcx(read_res),
                        Register::EDX => trapframe.set_rdx(read_res),
                        Register::R8D => trapframe.set_r8(read_res),
                        Register::R9D => trapframe.set_r9(read_res),
                        Register::R10D => trapframe.set_r10(read_res),
                        Register::R11D => trapframe.set_r11(read_res),
                        Register::R12D => trapframe.set_r12(read_res),
                        Register::R13D => trapframe.set_r13(read_res),
                        Register::R14D => trapframe.set_r14(read_res),
                        Register::R15D => trapframe.set_r15(read_res),
                        Register::ESI => trapframe.set_rsi(read_res),
                        Register::EDI => trapframe.set_rdi(read_res),
                        Register::EBP => trapframe.set_rbp(read_res),
                        Register::AX => {
                            trapframe.set_rax((trapframe.rax() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::BX => {
                            trapframe.set_rbx((trapframe.rbx() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::CX => {
                            trapframe.set_rcx((trapframe.rcx() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::DX => {
                            trapframe.set_rdx((trapframe.rdx() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::R8W => {
                            trapframe.set_r8((trapframe.r8() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::R9W => {
                            trapframe.set_r9((trapframe.r9() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::R10W => {
                            trapframe.set_r10((trapframe.r10() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::R11W => {
                            trapframe.set_r11((trapframe.r11() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::R12W => {
                            trapframe.set_r12((trapframe.r12() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::R13W => {
                            trapframe.set_r13((trapframe.r13() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::R14W => {
                            trapframe.set_r14((trapframe.r14() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::R15W => {
                            trapframe.set_r15((trapframe.r15() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::SI => {
                            trapframe.set_rsi((trapframe.rsi() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::DI => {
                            trapframe.set_rdi((trapframe.rdi() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::BP => {
                            trapframe.set_rbp((trapframe.rbp() & 0xFFFF_FFFF_FFFF_0000) | read_res)
                        }
                        Register::AL => {
                            trapframe.set_rax((trapframe.rax() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::BL => {
                            trapframe.set_rbx((trapframe.rbx() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::CL => {
                            trapframe.set_rcx((trapframe.rcx() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::DL => {
                            trapframe.set_rdx((trapframe.rdx() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::R8L => {
                            trapframe.set_r8((trapframe.r8() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::R9L => {
                            trapframe.set_r9((trapframe.r9() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::R10L => {
                            trapframe.set_r10((trapframe.r10() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::R11L => {
                            trapframe.set_r11((trapframe.r11() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::R12L => {
                            trapframe.set_r12((trapframe.r12() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::R13L => {
                            trapframe.set_r13((trapframe.r13() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::R14L => {
                            trapframe.set_r14((trapframe.r14() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::R15L => {
                            trapframe.set_r15((trapframe.r15() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::SIL => {
                            trapframe.set_rsi((trapframe.rsi() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::DIL => {
                            trapframe.set_rdi((trapframe.rdi() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        Register::BPL => {
                            trapframe.set_rbp((trapframe.rbp() & 0xFFFF_FFFF_FFFF_FF00) | read_res)
                        }
                        _ => return Err(MmioError::Unimplemented),
                    }
                },
                InstrMmioType::ReadZeroExtend =>
                // Safety: The mmio_gpa obtained from `ve_info` is valid, and the size parsed from the instruction is valid.
                unsafe {
                    let read_res = read_mmio(size, ve_info.guest_physical_address)
                        .map_err(MmioError::TdVmcallError)?
                        as usize;
                    match instr.op0_register() {
                        Register::RAX | Register::EAX | Register::AX | Register::AL => {
                            trapframe.set_rax(read_res)
                        }
                        Register::RBX | Register::EBX | Register::BX | Register::BL => {
                            trapframe.set_rbx(read_res)
                        }
                        Register::RCX | Register::ECX | Register::CX | Register::CL => {
                            trapframe.set_rcx(read_res)
                        }
                        Register::RDX | Register::EDX | Register::DX | Register::DL => {
                            trapframe.set_rdx(read_res)
                        }
                        Register::R8 | Register::R8D | Register::R8W | Register::R8L => {
                            trapframe.set_r8(read_res)
                        }
                        Register::R9 | Register::R9D | Register::R9W | Register::R9L => {
                            trapframe.set_r9(read_res)
                        }
                        Register::R10 | Register::R10D | Register::R10W | Register::R10L => {
                            trapframe.set_r10(read_res)
                        }
                        Register::R11 | Register::R11D | Register::R11W | Register::R11L => {
                            trapframe.set_r11(read_res)
                        }
                        Register::R12 | Register::R12D | Register::R12W | Register::R12L => {
                            trapframe.set_r12(read_res)
                        }
                        Register::R13 | Register::R13D | Register::R13W | Register::R13L => {
                            trapframe.set_r13(read_res)
                        }
                        Register::R14 | Register::R14D | Register::R14W | Register::R14L => {
                            trapframe.set_r14(read_res)
                        }
                        Register::R15 | Register::R15D | Register::R15W | Register::R15L => {
                            trapframe.set_r15(read_res)
                        }
                        Register::RSI | Register::ESI | Register::SI | Register::SIL => {
                            trapframe.set_rsi(read_res)
                        }
                        Register::RDI | Register::EDI | Register::DI | Register::DIL => {
                            trapframe.set_rdi(read_res)
                        }
                        Register::RBP | Register::EBP | Register::BP | Register::BPL => {
                            trapframe.set_rbp(read_res)
                        }
                        _ => return Err(MmioError::Unimplemented),
                    }
                },
                InstrMmioType::ReadSignExtend => return Err(MmioError::Unimplemented),
                // MMIO was accessed with an instruction that could not be decoded or handled properly.
                InstrMmioType::Movs => return Err(MmioError::InvalidInstruction),
            }
        }
        None => {
            return Err(MmioError::DecodeFailed);
        }
    }
    Ok(instr.len())
}

fn decode_instr(rip: usize) -> Result<Instruction, MmioError> {
    let code_data = {
        const MAX_X86_INSTR_LEN: usize = 15;
        let mut data = [0u8; MAX_X86_INSTR_LEN];
        // Safety:
        // This is safe because we are ensuring that 'rip' is a valid kernel virtual address before this operation.
        // We are also ensuring that the size of the data we are copying does not exceed 'MAX_X86_INSTR_LEN'.
        // Therefore, we are not reading any memory that we shouldn't be, and we are not causing any undefined behavior.
        unsafe {
            core::ptr::copy_nonoverlapping(rip as *const u8, data.as_mut_ptr(), data.len());
        }
        data
    };
    let mut decoder = Decoder::with_ip(64, &code_data, rip as u64, DecoderOptions::NONE);
    let mut instr = Instruction::default();
    decoder.decode_out(&mut instr);
    if instr.is_invalid() {
        return Err(MmioError::InvalidInstruction);
    }
    Ok(instr)
}

fn decode_mmio(instr: &Instruction) -> Option<(InstrMmioType, IoSize)> {
    match instr.code() {
        // 0x88
        Code::Mov_rm8_r8 => Some((InstrMmioType::Write, IoSize::Size1)),
        // 0x89
        Code::Mov_rm16_r16 => Some((InstrMmioType::Write, IoSize::Size2)),
        Code::Mov_rm32_r32 => Some((InstrMmioType::Write, IoSize::Size4)),
        Code::Mov_rm64_r64 => Some((InstrMmioType::Write, IoSize::Size8)),
        // 0xc6
        Code::Mov_rm8_imm8 => Some((InstrMmioType::WriteImm, IoSize::Size1)),
        // 0xc7
        Code::Mov_rm16_imm16 => Some((InstrMmioType::WriteImm, IoSize::Size2)),
        Code::Mov_rm32_imm32 => Some((InstrMmioType::WriteImm, IoSize::Size4)),
        Code::Mov_rm64_imm32 => Some((InstrMmioType::WriteImm, IoSize::Size8)),
        // 0x8a
        Code::Mov_r8_rm8 => Some((InstrMmioType::Read, IoSize::Size1)),
        // 0x8b
        Code::Mov_r16_rm16 => Some((InstrMmioType::Read, IoSize::Size2)),
        Code::Mov_r32_rm32 => Some((InstrMmioType::Read, IoSize::Size4)),
        Code::Mov_r64_rm64 => Some((InstrMmioType::Read, IoSize::Size8)),
        // 0xa4
        Code::Movsb_m8_m8 => Some((InstrMmioType::Movs, IoSize::Size1)),
        // 0xa5
        Code::Movsw_m16_m16 => Some((InstrMmioType::Movs, IoSize::Size2)),
        Code::Movsd_m32_m32 => Some((InstrMmioType::Movs, IoSize::Size4)),
        Code::Movsq_m64_m64 => Some((InstrMmioType::Movs, IoSize::Size8)),
        // 0x0f 0xb6
        Code::Movzx_r16_rm8 | Code::Movzx_r32_rm8 | Code::Movzx_r64_rm8 => {
            Some((InstrMmioType::ReadZeroExtend, IoSize::Size1))
        }
        // 0x0f 0xb7
        Code::Movzx_r16_rm16 | Code::Movzx_r32_rm16 | Code::Movzx_r64_rm16 => {
            Some((InstrMmioType::ReadZeroExtend, IoSize::Size2))
        }
        // 0x0f 0xbe
        Code::Movsx_r16_rm8 | Code::Movsx_r32_rm8 | Code::Movsx_r64_rm8 => {
            Some((InstrMmioType::ReadSignExtend, IoSize::Size1))
        }
        // 0x0f 0xbf
        Code::Movsx_r16_rm16 | Code::Movsx_r32_rm16 | Code::Movsx_r64_rm16 => {
            Some((InstrMmioType::ReadSignExtend, IoSize::Size2))
        }
        _ => None,
    }
}

enum InstrMmioType {
    Write,
    WriteImm,
    Read,
    ReadZeroExtend,
    ReadSignExtend,
    Movs,
}
