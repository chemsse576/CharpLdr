#pragma once
#include <cstddef>
#include <cstdint>

// Download a resource via raw TCP with realistic HTTP/1.1 headers
// Returns allocated buffer (caller must free) and sets out_size
// All Winsock calls go through resolved function pointers (no static imports)
unsigned char* download_payload(const char* host, const char* port, const char* resource, size_t* out_size);
