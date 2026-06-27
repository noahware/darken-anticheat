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

extern "C" runtime_function* RtlLookupFunctionEntry(
    ULONG64 ControlPc,
    PULONG64 ImageBase,
    PVOID HistoryTable
);

extern "C" PVOID RtlVirtualUnwind(
    ULONG HandlerType,
    ULONG64 ImageBase,
    ULONG64 ControlPc,
    runtime_function* FunctionEntry,
    PCONTEXT ContextRecord,
    PVOID* HandlerData,
    PULONG64 EstablisherFrame,
    PVOID ContextPointers
);

namespace nmi
{
    [[nodiscard]] cstd::vector<uint8_t> capture_rips();
}
