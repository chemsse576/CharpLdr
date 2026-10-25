;; syscalls.asm -- MASM x64
;; SyscallIndirect: bare indirect syscall stub (R11=SSN, R12=syscall_addr)
;; SpoofCallSyscall: stack-spoofing wrapper that forges fake frames then does the syscall
;;
;; Build: enable MASM in VS2022 (Build Customizations > masm)

; External symbols set by init_spoof() in stackspoof.cpp
EXTERN g_spoof_BaseThreadInitThunk : QWORD   ; address of kernel32!BaseThreadInitThunk+N (a ret gadget)
EXTERN g_spoof_RtlUserThreadStart  : QWORD   ; address of ntdll!RtlUserThreadStart+N (a ret gadget)
EXTERN g_spoof_gadget_jmp_rbx     : QWORD   ; address of a "jmp [rbx]" or "jmp rbx" gadget in kernel32

.code

;; ============================================================================
;; SyscallIndirect - Bare indirect syscall (no spoofing)
;; Convention: RCX=arg1, RDX=arg2, R8=arg3, R9=arg4, stack args as normal
;;             R11=SSN, R12=syscall_addr
;; Caller must save/restore R11, R12 (callee-saved)
;; ============================================================================
SyscallIndirect PROC
    mov r10, rcx            ; Windows syscall convention: first arg in R10
    mov eax, r11d           ; SSN from R11 (low 32 bits)
    jmp r12                 ; jump to syscall;ret in ntdll
SyscallIndirect ENDP

;; ============================================================================
;; SpoofCallSyscall - Stack-spoofing indirect syscall
;;
;; C prototype:
;;   NTSTATUS SpoofCallSyscall(
;;       void* arg1,  void* arg2,  void* arg3,  void* arg4,    // RCX, RDX, R8, R9
;;       void* arg5,  void* arg6,  void* arg7,  void* arg8,    // [RSP+28h..48h]
;;       void* arg9,  void* arg10, void* arg11, void* arg12,   // [RSP+48h..68h]
;;       uint32_t ssn,                                          // [RSP+68h]
;;       void* syscall_addr                                     // [RSP+70h]
;;   );
;;
;; This function:
;; 1. Saves callee-saved registers and the real return state
;; 2. Reads SSN and syscall_addr from the stack args
;; 3. Constructs synthetic stack frames mimicking a legitimate thread
;; 4. Places syscall args and executes the indirect syscall
;; 5. On return, restores the real stack and returns to caller
;; ============================================================================
SpoofCallSyscall PROC
    ; === Prologue: save callee-saved registers ===
    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 28h                ; shadow space for our calls + alignment

    ; Save the real caller state
    ; At this point:
    ;   RSP has been adjusted by pushes (8*8=64=40h) + sub 28h = 68h from entry RSP
    ;   Entry RSP+0 had the return address
    ;   Args were at: RCX, RDX, R8, R9, [entry_RSP+28h], [entry_RSP+30h], ...
    ;   After our pushes+sub: original stack args are at RSP + 68h + 28h = RSP + 90h

    ; The original stack layout (from C caller) before our PROC was called:
    ;   [entry_RSP + 00h] = return address (pushed by CALL)
    ;   [entry_RSP + 08h] = shadow space (RCX home)
    ;   [entry_RSP + 10h] = shadow space (RDX home)
    ;   [entry_RSP + 18h] = shadow space (R8 home)
    ;   [entry_RSP + 20h] = shadow space (R9 home)
    ;   [entry_RSP + 28h] = arg5
    ;   [entry_RSP + 30h] = arg6
    ;   ...
    ;   [entry_RSP + 68h] = ssn (arg13)
    ;   [entry_RSP + 70h] = syscall_addr (arg14)

    ; Our frame: 8 pushes (40h) + sub 28h = 68h below entry RSP
    ; entry RSP = current RSP + 68h
    ; So original [entry_RSP + X] = [RSP + 68h + X]

    ; Save the 4 register args for later
    mov r13, rcx                ; arg1
    mov r14, rdx                ; arg2
    mov r15, r8                 ; arg3
    mov rsi, r9                 ; arg4

    ; Load SSN and syscall_addr from stack
    ; ssn    is at [entry_RSP + 68h] = [RSP + 68h + 68h] = [RSP + 0D0h]
    ; sysaddr is at [entry_RSP + 70h] = [RSP + 68h + 70h] = [RSP + 0D8h]
    mov r11d, dword ptr [rsp + 0D0h]    ; SSN
    mov r12, qword ptr [rsp + 0D8h]     ; syscall_addr

    ; === Build the spoofed stack ===
    ; We need a new stack area for the syscall with fake frames.
    ; Save current RSP so we can restore it later.
    mov rbx, rsp                ; save real RSP in RBX

    ; Allocate a large chunk on the stack for fake frames + syscall args
    ; We need: shadow space (20h) + up to 10 stack args (50h) + fake frames (40h) + alignment
    ; Total: ~100h should be plenty
    sub rsp, 100h
    and rsp, 0FFFFFFFFFFFFFFF0h  ; 16-byte align

    ; Build fake frame chain (from bottom to top):
    ; Frame 3 (terminator):   RBP=0, ret=0
    ; Frame 2:                RBP->frame3, ret=RtlUserThreadStart+N
    ; Frame 1:                RBP->frame2, ret=BaseThreadInitThunk+N
    ; Current:                RBP->frame1

    ; We'll place the fake frames at the bottom of our allocated area
    ; Layout at RSP:
    ;   [RSP + 00h] = return address for syscall (the syscall;ret will ret here... but we use jmp)
    ;   [RSP + 08h..27h] = shadow space for syscall
    ;   [RSP + 28h..] = stack args for syscall (args 5+)

    ; Place fake frames above the syscall area
    ; Fake frame 3 (terminator) at RSP+E0h
    mov qword ptr [rsp + 0E0h], 0       ; saved RBP = NULL (end of chain)
    mov qword ptr [rsp + 0E8h], 0       ; return addr = 0

    ; Fake frame 2 at RSP+D0h
    lea rax, [rsp + 0E0h]
    mov qword ptr [rsp + 0D0h], rax     ; saved RBP -> frame 3
    mov rax, qword ptr [g_spoof_RtlUserThreadStart]
    mov qword ptr [rsp + 0D8h], rax     ; return addr = RtlUserThreadStart+N

    ; Fake frame 1 at RSP+C0h
    lea rax, [rsp + 0D0h]
    mov qword ptr [rsp + 0C0h], rax     ; saved RBP -> frame 2
    mov rax, qword ptr [g_spoof_BaseThreadInitThunk]
    mov qword ptr [rsp + 0C8h], rax     ; return addr = BaseThreadInitThunk+N

    ; Set RBP to point to fake frame 1
    lea rbp, [rsp + 0C0h]

    ; === Place syscall arguments ===
    ; Args 5-10 go on the stack at RSP+28h, RSP+30h, etc.
    ; arg5 was at [rbx + 68h + 28h] = [rbx + 90h]
    ; arg6 was at [rbx + 68h + 30h] = [rbx + 98h]
    ; ...up to arg12

    mov rax, qword ptr [rbx + 90h]      ; arg5
    mov qword ptr [rsp + 28h], rax
    mov rax, qword ptr [rbx + 98h]      ; arg6
    mov qword ptr [rsp + 30h], rax
    mov rax, qword ptr [rbx + 0A0h]     ; arg7
    mov qword ptr [rsp + 38h], rax
    mov rax, qword ptr [rbx + 0A8h]     ; arg8
    mov qword ptr [rsp + 40h], rax
    mov rax, qword ptr [rbx + 0B0h]     ; arg9
    mov qword ptr [rsp + 48h], rax
    mov rax, qword ptr [rbx + 0B8h]     ; arg10
    mov qword ptr [rsp + 50h], rax
    mov rax, qword ptr [rbx + 0C0h]     ; arg11
    mov qword ptr [rsp + 58h], rax
    mov rax, qword ptr [rbx + 0C8h]     ; arg12
    mov qword ptr [rsp + 60h], rax

    ; Restore syscall register args
    mov rcx, r13                ; arg1
    mov rdx, r14                ; arg2
    mov r8, r15                 ; arg3
    mov r9, rsi                 ; arg4

    ; === Execute the indirect syscall ===
    ; R11 = SSN (already set), R12 = syscall_addr (already set)
    mov r10, rcx                ; Windows syscall ABI: first arg in R10
    mov eax, r11d               ; SSN
    jmp_to_syscall:
    ; We use CALL so we get a return address on the stack
    ; But we want the stack to look clean. Instead, we push a return label and jmp.
    lea rax, [syscall_return]
    mov qword ptr [rsp], rax    ; set return address at top of stack
    jmp r12                     ; jump to syscall;ret in ntdll

    syscall_return:
    ; RAX = NTSTATUS result from syscall

    ; === Epilogue: restore real stack ===
    mov rsp, rbx                ; restore saved RSP

    add rsp, 28h                ; undo sub rsp, 28h
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
