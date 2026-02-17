.code

DoSyscall PROC
    ; Arguments:
    ; RCX = Syscall Index
    ; RDX = Parameters Array Pointer
    ; R8D = Parameter Count

    ; Save non-volatile registers
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    
    mov rbp, rsp        ; Save stack pointer
    
    mov r13d, ecx       ; Save Syscall Index
    mov r12, rdx        ; Save Params Array
    mov ebx, r8d        ; Save Count
    
    ; Calculate stack size needed
    ; Size = 32 (Shadow) + 8 (Alignment/FakeRet) + max(0, Count-4)*8
    ; Align to 16 bytes
    
    mov eax, ebx
    sub eax, 4
    cmp eax, 0
    jg calc_size
    xor eax, eax        ; 0 if Count <= 4
calc_size:
    shl eax, 3          ; * 8
    add eax, 40         ; 32 (Shadow) + 8 (Alignment/FakeRet)
    
    ; Align to 16 bytes
    add eax, 15
    and eax, -16
    
    sub rsp, rax        ; Allocate stack
    
    ; Load stack args (Arg5+)
    cmp ebx, 4
    jle load_stack_args_end
    
    mov rsi, 4
store_stack_args:
    cmp rsi, rbx
    jge load_stack_args_end
    
    mov rax, qword ptr [r12 + rsi*8]
    ; Store at [RSP + rsi*8 + 8]
    ; rsi=4 -> 32 + 8 = 40 (0x28) (Correct location for Arg5)
    mov qword ptr [rsp + rsi*8 + 8], rax
    
    inc rsi
    jmp store_stack_args

load_stack_args_end:
    
load_regs:
    ; Load register args
    ; R10 = Arg1, RDX = Arg2, R8 = Arg3, R9 = Arg4
    
    xor r10, r10
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    
    cmp ebx, 0
    je do_syscall_inst
    mov r10, qword ptr [r12 + 0]
    
    cmp ebx, 1
    je do_syscall_inst
    mov rdx, qword ptr [r12 + 8]
    
    cmp ebx, 2
    je do_syscall_inst
    mov r8, qword ptr [r12 + 16]
    
    cmp ebx, 3
    je do_syscall_inst
    mov r9, qword ptr [r12 + 24]

do_syscall_inst:
    mov eax, r13d       ; Restore Syscall Index
    syscall
    
    ; Restore stack
    mov rsp, rbp
    
    ; Restore regs
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    
    ret
DoSyscall ENDP

END