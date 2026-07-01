#pragma once
#include <ntifs.h>

namespace krnl
{
    inline void sleep_ms(const uint32_t ms) noexcept
    {
        LARGE_INTEGER interval;
        interval.QuadPart = -static_cast<int64_t>(ms) * 10000;
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}
