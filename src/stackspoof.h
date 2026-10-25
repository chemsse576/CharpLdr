#pragma once
#include <cstdint>

// Call stack spoofing infrastructure
// Scans kernel32 and ntdll at init for gadgets used by SpoofCallSyscall in syscalls.asm

// Global addresses used by the ASM stub (set-once during init, read-only after)
extern "C" {
    extern uint64_t g_spoof_BaseThreadInitThunk;   // kernel32!BaseThreadInitThunk + offset (ret gadget)
    extern uint64_t g_spoof_RtlUserThreadStart;    // ntdll!RtlUserThreadStart + offset (ret gadget)
    extern uint64_t g_spoof_gadget_jmp_rbx;        // jmp [rbx] gadget in kernel32
}

// Scan kernel32 and ntdll to populate the global gadget addresses
bool init_spoof();
