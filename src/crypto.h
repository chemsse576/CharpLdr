#pragma once
#include <cstddef>
#include <cstdint>

// RC4 custom implementation (no SystemFunction032 dependency)
void rc4(unsigned char* data, size_t data_len, const unsigned char* key, size_t key_len);

// Get the hardcoded RC4 key (obfuscated at compile-time)
// Returns the key and sets key_len
const unsigned char* get_rc4_key(size_t* key_len);

// Decrypt a buffer in-place using the hardcoded RC4 key
void decrypt_payload(unsigned char* data, size_t data_len);
