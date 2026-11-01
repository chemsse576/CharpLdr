#pragma once
#include "config.h"

bool execute_assembly(unsigned char* payload, size_t payload_size,
                      const char** args, int argc,
                      const LoaderConfig* config);
