; File: asmSyscall.asm
; Author: Gregory King
; Date: September 7, 2025
; Description: Direct syscall implementation for BYOVD toolkit
; Architecture: x64 only

.code

; NTSTATUS DoSyscall(DWORD syscallIndex, PVOID* params, ULONG paramCount)
; RCX = syscallIndex
; RDX = params array pointer
; R8 = paramCount
DoSyscall PROC
    ; Save registers that might be modified
    push r10
    push r11
    push r12
    push r13
    
    ; Save original parameters
    mov r12, rdx    ; Save params array pointer
    mov r13, r8     ; Save parameter count
    
    ; Move syscall index to EAX (required for syscall)
    mov eax, ecx
    
    ; Set up syscall parameters in proper registers
    ; Windows x64 syscall convention:
    ; RCX, RDX, R8, R9 for first 4 parameters
    
    ; Check if we have parameters to set up
    test r12, r12
    jz no_params
    test r13, r13
    jz no_params
    
    ; Load first parameter into RCX
    mov rcx, qword ptr [r12]
    cmp r13, 1
    je do_syscall
    
    ; Load second parameter into RDX
    mov rdx, qword ptr [r12 + 8]
    cmp r13, 2
    je do_syscall
    
    ; Load third parameter into R8
    mov r8, qword ptr [r12 + 16]
    cmp r13, 3
    je do_syscall
    
    ; Load fourth parameter into R9
    mov r9, qword ptr [r12 + 24]
    cmp r13, 4
    je do_syscall
    
    ; For more than 4 parameters, push additional ones onto stack
    ; Stack parameters are pushed in reverse order
    mov r11, r13
    sub r11, 4          ; Number of stack parameters
    
push_params:
    test r11, r11
    jz do_syscall
    dec r11
    push qword ptr [r12 + 32 + r11 * 8]
    jmp push_params
    
no_params:
    ; Zero out registers if no parameters
    xor rcx, rcx
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    
do_syscall:
    ; Set up syscall instruction
    ; R10 = RCX (syscall convention requirement)
    mov r10, rcx
    
    ; Execute the syscall
    syscall
    
    ; Clean up stack if we pushed extra parameters
    cmp r13, 4
    jle cleanup
    mov r11, r13
    sub r11, 4
    lea rsp, [rsp + r11 * 8]
    
cleanup:
    ; Restore registers
    pop r13
    pop r12
    pop r11
    pop r10
    
    ; Return value is already in RAX
    ret
DoSyscall ENDP

END