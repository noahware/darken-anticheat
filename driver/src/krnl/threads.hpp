#pragma once
#include <ntifs.h>
#include <vector.hpp>

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

namespace krnl
{
    [[nodiscard]] cstd::vector<uint8_t> get_thread_list();
}
