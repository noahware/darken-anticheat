#include "msr.hpp"
#include "reserved_msr_result_generated.h"
#include "../log.hpp"
#include "../util/serialisation.hpp"

#include <ntifs.h>
#include <intrin.h>

cstd::vector<uint8_t> msr::test_reserved()
{
    for (uint32_t i = 0x40000000u; i <= 0x4000FFFFu; i++)
    {
        __try
        {
            __readmsr(i);

            DBG_LOG("found usage of reserved MSR 0x%x.\n", i);

            return serialisation::serialise(serialisation::lift<Anticheat::CreateReservedMsrResult>(), i);
        }
        __except (1)
        {

        }
    }

    return serialisation::serialise(serialisation::lift<Anticheat::CreateReservedMsrResult>(), flatbuffers::nullopt);
}
