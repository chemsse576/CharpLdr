#pragma once
#include <cstdint>
#include <string>
#include <cstring>

// Compile-time string encryption via XOR with key derived from __LINE__ and __COUNTER__
//
// USAGE PATTERN (CRITICAL for Release /O2 builds):
//   auto s = OBFSTR("amsi.dll");   // extend lifetime via named variable
//   use(s.c_str());                 // safe, s is alive
//   // s destroyed here (auto-zeroed by destructor)
//
// NEVER DO: use(OBFSTR("amsi.dll").c_str()) -- dangling pointer in Release!

namespace obf {

constexpr uint8_t xor_key(uint32_t seed, size_t idx) {
    uint32_t k = seed ^ static_cast<uint32_t>(idx * 0x41C64E6D + 0x3039);
    k = (k >> 16) ^ k;
    return static_cast<uint8_t>(k & 0xFF);
}

template<size_t N>
struct ObfString {
    char data[N];
    uint32_t seed;

    constexpr ObfString(const char(&str)[N], uint32_t s) : data{}, seed(s) {
        for (size_t i = 0; i < N; i++) {
            data[i] = str[i] ^ static_cast<char>(xor_key(s, i));
        }
    }

    std::string decrypt() const {
        char buf[N];
        for (size_t i = 0; i < N; i++) {
            buf[i] = data[i] ^ static_cast<char>(xor_key(seed, i));
        }
        std::string result(buf, N - 1);
        volatile char* vbuf = reinterpret_cast<volatile char*>(buf);
        for (size_t i = 0; i < N; i++) vbuf[i] = 0;
        return result;
    }
};

template<size_t N>
struct ObfWString {
    wchar_t data[N];
    uint32_t seed;

    constexpr ObfWString(const wchar_t(&str)[N], uint32_t s) : data{}, seed(s) {
        for (size_t i = 0; i < N; i++) {
            data[i] = str[i] ^ static_cast<wchar_t>(xor_key(s, i));
        }
    }

    std::wstring decrypt() const {
        wchar_t buf[N];
        for (size_t i = 0; i < N; i++) {
            buf[i] = data[i] ^ static_cast<wchar_t>(xor_key(seed, i));
        }
        std::wstring result(buf, N - 1);
        volatile wchar_t* vbuf = reinterpret_cast<volatile wchar_t*>(buf);
        for (size_t i = 0; i < N; i++) vbuf[i] = 0;
        return result;
    }
};

} // namespace obf

#define _OBF_SEED_ (static_cast<uint32_t>(__LINE__) * 2654435761u ^ static_cast<uint32_t>(__COUNTER__) * 340573321u)

#define OBFSTR(str) \
    ([]() -> std::string { \
        constexpr auto _obf = ::obf::ObfString<sizeof(str)>(str, _OBF_SEED_); \
        return _obf.decrypt(); \
    }())

#define OBFWSTR(str) \
    ([]() -> std::wstring { \
        constexpr auto _obf = ::obf::ObfWString<sizeof(str)/sizeof(wchar_t)>(str, _OBF_SEED_); \
        return _obf.decrypt(); \
    }())
