#pragma once

// ntdll + kernelbase unhooking by replacing .text with fresh copies
// All operations use indirect syscalls (resolved before unhooking)
bool unhook_ntdll();
bool unhook_kernelbase();
bool unhook_all();
