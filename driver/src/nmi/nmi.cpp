#include "nmi.hpp"
#include "../log.hpp"
#include "../krnl/time.hpp"

#include "flatbuffers/flatbuffers.h"
#include "nmi_result_generated.h"

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

        const auto processor_count = KeQueryActiveProcessorCount(nullptr);

        if (processor_count == 0)
        {
            return {};
        }

        cstd::vector<nmi_core_info> core_info(processor_count, nmi_core_info{});

        const auto callback_handle = KeRegisterNmiCallback(nmi_callback_handler, core_info.data());

        if (!callback_handle)
        {
            DBG_LOG("capture_rips: failed to register NMI callback\n");
            return {};
        }

        const auto current_core = static_cast<uint32_t>(__readgsbyte(0x184));
        const auto old_affinity = KeSetSystemAffinityThreadEx(1ull << current_core);

        _KAFFINITY_EX affinity;

        for (uint32_t i = 0; i < processor_count; ++i)
        {
            if (i == current_core)
            {
                continue;
            }

            KeInitializeAffinityEx(&affinity);
            KeAddProcessorAffinityEx(&affinity, i);
            HalSendNMI(&affinity);
        }

        KeRevertToUserAffinityThreadEx(old_affinity);

        krnl::sleep_ms(10);

        KeDeregisterNmiCallback(callback_handle);

        flatbuffers::FlatBufferBuilder fbb(256 + processor_count * 16);
        cstd::vector<flatbuffers::Offset<Anticheat::NmiCoreCapture>> capture_offsets;

        for (uint32_t i = 0; i < processor_count; ++i)
        {
            capture_offsets.push_back(
                Anticheat::CreateNmiCoreCapture(fbb, core_info[i].rip, core_info[i].cs, core_info[i].processed)
            );
        }

        auto captures_vec = fbb.CreateVector(capture_offsets.data(), capture_offsets.size());
        auto result = Anticheat::CreateNmiResult(fbb, captures_vec, current_core);
        fbb.Finish(result);

        const auto* buf = fbb.GetBufferPointer();
        const auto size = fbb.GetSize();

        DBG_LOG("capture_rips: %u cores, %u bytes\n", processor_count, size);

        return cstd::vector<uint8_t>(buf, size);
    }
}
