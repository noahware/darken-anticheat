#include "modules.hpp"
#include "../log.hpp"

#include <string.hpp>
#include <span.hpp>

#include "flatbuffers/flatbuffers.h"
#include "kernel_modules_generated.h"
#include "../util/serialisation.hpp"

namespace krnl
{
    cstd::expected<crypto::sha256_hash_t, nt_status> hash_nonwritable_sections(
        portable_executable::image_t* image)
    {
        const auto base = reinterpret_cast<const uint8_t*>(image);
        cstd::vector<cstd::span<const uint8_t>> chunks;

        for (const auto& sec : image->sections())
        {
            if (sec.characteristics.mem_write || sec.characteristics.mem_discardable)
            {
                continue;
            }

            chunks.push_back(cstd::span<const uint8_t>(
                base + sec.virtual_address, sec.virtual_size
            ));
        }

        return crypto::sha256(cstd::span<const cstd::span<const uint8_t>>(
            chunks.data(), chunks.size()
        ));
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

        flatbuffers::FlatBufferBuilder fbb;

        auto modules_vec = serialisation::collect<Anticheat::KernelModule>(fbb, module_list{},
            [](auto& b, const auto& mod)
            {
                const auto narrow_name = cstd::to_string(mod.base_name());
                const auto narrow_path = cstd::to_string(mod.full_name());
                const auto hash_result = hash_nonwritable_sections(mod.image());

                auto name_offset = b.CreateString(narrow_name.data(), narrow_name.size());
                auto path_offset = b.CreateString(narrow_path.data(), narrow_path.size());

                flatbuffers::Offset<flatbuffers::Vector<uint8_t>> hash_offset;

                if (hash_result)
                {
                    hash_offset = b.CreateVector(
                        hash_result.value().data(), crypto::sha256_size
                    );
                }
                else
                {
                    DBG_LOG("hash failed for %s: 0x%x\n",
                        narrow_name.data(), hash_result.error());
                }

                return Anticheat::CreateKernelModule(
                    b,
                    mod.base_address(),
                    mod.size_of_image(),
                    name_offset,
                    hash_offset,
                    path_offset
                );
            });

        auto result = serialisation::serialise(fbb, serialisation::lift<Anticheat::CreateKernelModuleList>(), modules_vec);

        DBG_LOG("module list: %zu bytes\n", result.size());

        return result;
    }
}
