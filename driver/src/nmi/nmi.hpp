#pragma once
#include <ntifs.h>
#include <vector.hpp>

#include "../krnl/types.hpp"

extern "C" void HalSendNMI(
    _KAFFINITY_EX* Affinity
);

extern "C" void KeInitializeAffinityEx(
    _KAFFINITY_EX* Affinity
);

extern "C" void KeAddProcessorAffinityEx(
    _KAFFINITY_EX* Affinity,
    ULONG ProcessorNumber
);

namespace nmi
{
    [[nodiscard]] cstd::vector<uint8_t> capture_rips();
}
