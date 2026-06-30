#include "nmi.hpp"
#include "../log.hpp"
#include "../krnl/time.hpp"
#include "../util/import.hpp"

#include "flatbuffers/flatbuffers.h"
#include "nmi_result_generated.h"
#include "../util/serialisation.hpp"

namespace
{
    struct nmi_core_info
    {
        uint64_t rip;
        uint64_t cs;
        bool processed;
    };

    constexpr uint64_t kpcr_tss_base_offset = 0x8;
    constexpr uint64_t tss_ist3_offset = 0x34;

    BOOLEAN nmi_callback_handler(PVOID context, BOOLEAN)
    {
        auto* core_info = static_cast<nmi_core_info*>(context);
        const auto processor_number = __readgsbyte(0x184);

        auto& info = core_info[processor_number];

        if (info.processed)
        {
            return TRUE;
        }

        const auto pcr = __readgsqword(0x18);
        const auto tss_base = *reinterpret_cast<uint64_t*>(pcr + kpcr_tss_base_offset);
        const auto ist3 = *reinterpret_cast<uint64_t*>(tss_base + tss_ist3_offset);
        const auto* frame = reinterpret_cast<machine_frame*>(ist3 - sizeof(machine_frame));

        info.rip = frame->rip;
        info.cs = frame->cs;
        info.processed = true;

        return TRUE;
    }
}

namespace nmi
{
    cstd::vector<uint8_t> capture_rips()
    {
        DBG_LOG("capture_rips: entering\n");

        const auto processor_count = LIMPORT(KeQueryActiveProcessorCount)(nullptr);

        if (processor_count == 0)
        {
            return {};
        }

        cstd::vector<nmi_core_info> core_info(processor_count, nmi_core_info{});

        const auto callback_handle = LIMPORT(KeRegisterNmiCallback)(nmi_callback_handler, core_info.data());

        if (!callback_handle)
        {
            DBG_LOG("capture_rips: failed to register NMI callback\n");
            return {};
        }

        const auto current_core = static_cast<uint32_t>(__readgsbyte(0x184));
        const auto old_affinity = LIMPORT(KeSetSystemAffinityThreadEx)(1ull << current_core);

        _KAFFINITY_EX affinity;

        for (uint32_t i = 0; i < processor_count; ++i)
        {
            if (i == current_core)
            {
                continue;
            }

            LIMPORT(KeInitializeAffinityEx)(&affinity);
            LIMPORT(KeAddProcessorAffinityEx)(&affinity, i);
            LIMPORT(HalSendNMI)(&affinity);
        }

        LIMPORT(KeRevertToUserAffinityThreadEx)(old_affinity);

        krnl::sleep_ms(10);

        LIMPORT(KeDeregisterNmiCallback)(callback_handle);

        flatbuffers::FlatBufferBuilder fbb;

        auto captures_vec = serialisation::collect<Anticheat::NmiCoreCapture>(fbb, core_info,
            [](auto& b, const auto& info)
            {
                return Anticheat::CreateNmiCoreCapture(b, info.rip, info.cs, info.processed);
            });
        auto result = serialisation::serialise(fbb, serialisation::lift<Anticheat::CreateNmiResult>(), captures_vec, current_core);

        DBG_LOG("capture_rips: %u cores, %zu bytes\n", processor_count, result.size());

        return result;
    }
}
