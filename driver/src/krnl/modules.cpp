#include "modules.hpp"
#include "../log.hpp"

#include <string.hpp>
#include <hash.hpp>

#include "flatbuffers/flatbuffers.h"
#include "kernel_modules_generated.h"

namespace krnl
{
    cstd::hash_type hash_nonwritable_sections(portable_executable::image_t* image)
    {
        constexpr cstd::hash_type basis = 0xcbf29ce484222325;
        constexpr cstd::hash_type prime = 0x100000001B3;

        auto hash = basis;
        const auto base = reinterpret_cast<uint8_t*>(image);

        for (const auto& sec : image->sections())
        {
            if (sec.characteristics.mem_write || sec.characteristics.mem_discardable)
            {
                continue;
            }

            const auto* data = base + sec.virtual_address;
            const auto size = sec.virtual_size;

            for (uint32_t i = 0; i < size; ++i)
            {
                hash ^= data[i];
                hash *= prime;
            }
        }

        return hash;
    }

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
            const auto hash = hash_nonwritable_sections(mod.image());
            auto name_offset = fbb.CreateString(narrow_name.data(), narrow_name.size());
            auto module = Anticheat::CreateKernelModule(
                fbb,
                mod.base_address(),
                mod.size_of_image(),
                name_offset,
                hash
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
