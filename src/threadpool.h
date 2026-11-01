#pragma once
#include "config.h"
#include <cstddef>

struct TpCallbackContext {
    unsigned char* payload;
    size_t payload_size;
    const char** args;
    int argc;
    const LoaderConfig* config;
    void* token;
    bool success;
    bool completed;
};

bool execute_via_threadpool(unsigned char* payload, size_t payload_size,
                            const char** args, int argc,
                            const LoaderConfig* config);
