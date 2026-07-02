#include "data_page_exec.hpp"
#include "../krnl/modules.hpp"
#include "flatbuffers/flatbuffers.h"
#include "kernel_data_page_exec_result_generated.h"
#include "mem.hpp"
#include "../log.hpp"
#include "../util/serialisation.hpp"

struct data_page_exec_info
{
    uintptr_t image_base;
    uint32_t rva;
};

static void collect_exec_data_pages(cstd::vector<data_page_exec_info>& infos, const krnl::module& mod)
{
    const auto img = mod.image();

    for (const auto& sec : img->sections())
    {
        if (sec.characteristics.mem_execute)
        {
            continue;
        }

        const uintptr_t base_addr = mod.base_address();
        const uint32_t rva = sec.virtual_address;
        const uint32_t end_rva = rva + sec.virtual_size;

        for (uint32_t i = rva; i < end_rva; i += mem::page_size)
        {
            const auto page_flags = mem::virt_page_flags(mem::curr_cr3(), base_addr + i);

            /*// todo: maybe communicate page flags==none to server
            if (page_flags == page_none)
            {
                DBG_LOG("unable to get page flags for kernel virt addr 0x%llx\n", base_addr + i);
            }*/

            if (page_flags & page_execute)
            {
                infos.emplace_back(base_addr, i);
            }
        }
    }
}

cstd::vector<uint8_t> mem::data_page_exec_check()
{
    cstd::vector<data_page_exec_info> infos;

    for (const auto& mod : krnl::module_list{})
    {
        collect_exec_data_pages(infos, mod);
    }

    flatbuffers::FlatBufferBuilder fbb;

    auto handles_vec = serialisation::collect<Anticheat::KernelPagePteExecEntry>(fbb, infos,
        [](auto& b, const auto& info)
        {
            return Anticheat::CreateKernelPagePteExecEntry(b, info.image_base, info.rva);
        });

    return serialisation::serialise(fbb, serialisation::lift<Anticheat::CreateKernelDataPageExecCheckResult>(), handles_vec);
}
