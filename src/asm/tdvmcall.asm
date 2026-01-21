# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2023-2024 Intel Corporation.

.section .text

# Mask used to control which part of the guest TD GPR and XMM
# state is exposed to the VMM. A bit value of 1 indicates the
# corresponding register is passed to VMM. Refer to TDX Module
# ABI specification section TDG.VP.VMCALL for detail.
# Here we expose R10 - R15 to VMM in td_vm_call()
.equ TDVMCALL_EXPOSE_REGS_MASK, 0xfc00
.equ TDVMCALL, 0

.equ VMCALL_R8, 0x0
.equ VMCALL_R9, 0x8
.equ VMCALL_R10, 0x10
.equ VMCALL_R11, 0x18
.equ VMCALL_R12, 0x20
.equ VMCALL_R13, 0x28
.equ VMCALL_R14, 0x30
.equ VMCALL_R15, 0x38
.equ VMCALL_RBX, 0x40
.equ VMCALL_RCX, 0x48
.equ VMCALL_RDI, 0x50
.equ VMCALL_RSI, 0x58
.equ VMCALL_RDX, 0x60

.align 16

.global asm_td_vmcall
asm_td_vmcall:
        endbr64

        test rdi, rdi
        jz .L_invalid_input

        push rbp
        mov rbp, rsp
        push rbx
        push r12
        push r13
        push r14
        push r15

        push rdi

        mov r8,  [rdi + VMCALL_R8]
        mov r9,  [rdi + VMCALL_R9]
        mov r10, [rdi + VMCALL_R10]
        mov r11, [rdi + VMCALL_R11]
        mov r12, [rdi + VMCALL_R12]
        mov r13, [rdi + VMCALL_R13]
        mov r14, [rdi + VMCALL_R14]
        mov r15, [rdi + VMCALL_R15]
        mov rbx, [rdi + VMCALL_RBX]
        mov rsi, [rdi + VMCALL_RSI]
        mov rdx, [rdi + VMCALL_RDX]

        mov rcx, [rdi + VMCALL_RCX]
        or  rcx, TDVMCALL_EXPOSE_REGS_MASK

        mov rdi, [rdi + VMCALL_RDI]

        mov rax, TDVMCALL

        .byte 0x66, 0x0f, 0x01, 0xcc

        pop rdi

        test rax, rax
        jnz .L_tdcall_failed

        mov [rdi + VMCALL_R10], r10
        mov [rdi + VMCALL_R11], r11
        mov [rdi + VMCALL_R12], r12
        mov [rdi + VMCALL_R13], r13
        mov [rdi + VMCALL_R14], r14
        mov [rdi + VMCALL_R15], r15

        mov rax, r10

.L_cleanup:
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret

.L_invalid_input:
        mov rax, -1
        ret

.L_tdcall_failed:
        # Set a specific error code.
        mov rax, -2
        jmp .L_cleanup
