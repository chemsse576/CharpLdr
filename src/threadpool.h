#pragma once

// NT ThreadPool execution using TpAllocWork/TpPostWork/TpReleaseWork
// Avoids CreateThread and PsSetCreateThreadNotifyRoutine callbacks

// Context passed to the threadpool callback
struct TpCallbackContext {
    unsigned char* payload;
    size_t payload_size;
    const char** args;
    int argc;
    bool success;
    bool completed;
};

// Execute the assembly loading via NT ThreadPool
// Blocks until the callback completes
bool execute_via_threadpool(unsigned char* payload, size_t payload_size,
                            const char** args, int argc);
