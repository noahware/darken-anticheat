#include "modules.hpp"
#include "../log.hpp"

#include <string.hpp>

#include "flatbuffers/flatbuffers.h"
#include "kernel_modules_generated.h"

namespace krnl
{
    portable_executable::image_t* find_module_image(cstd::wstring_view module_name)
    {
        for (const auto& mod : module_list{})
        {
            if (module_name == mod.base_name())
            {
                return mod.image();
            }
        }

        return nullptr;
    }

    cstd::vector<uint8_t> get_module_list()
    {
        DBG_LOG("get_module_list: entering\n");

        cstd::vector<flatbuffers::Offset<Anticheat::KernelModule>> module_offsets;
        flatbuffers::FlatBufferBuilder fbb(4096);

        for (const auto& mod : module_list{})
        {
            const auto narrow_name = cstd::to_string(mod.base_name());
            auto name_offset = fbb.CreateString(narrow_name.data(), narrow_name.size());
            auto module = Anticheat::CreateKernelModule(
                fbb,
                mod.base_address(),
                mod.size_of_image(),
                name_offset
            );

            module_offsets.push_back(module);
        }

        auto modules_vec = fbb.CreateVector(module_offsets.data(), module_offsets.size());
        auto list = Anticheat::CreateKernelModuleList(fbb, modules_vec);
        fbb.Finish(list);

        const auto* buf = fbb.GetBufferPointer();
        const auto size = fbb.GetSize();

        DBG_LOG("module list: %zu modules, %u bytes\n", module_offsets.size(), size);

        return cstd::vector<uint8_t>(buf, size);
    }
}
