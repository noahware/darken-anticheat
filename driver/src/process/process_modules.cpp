#include "process_modules.hpp"
#include "../log.hpp"
#include "../state/protected_process.hpp"
#include "../crypto/crypto.hpp"
#include "../util/serialisation.hpp"
#include "../util/import.hpp"
#include "../krnl/types.hpp"
#include "../krnl/modules.hpp"

#include <ntifs.h>
#include <string.hpp>
#include <portable_executable/image.hpp>

#include "flatbuffers/flatbuffers.h"
#include "protected_process_generated.h"

namespace
{
    extern "C" PPEB PsGetProcessPeb(PEPROCESS process);

    struct module_snapshot
    {
        uint64_t base_address;
        uint32_t size_of_image;
        cstd::string name;
        cstd::string full_path;
        cstd::expected<crypto::sha256_hash_t, nt_status> hash;
    };

    cstd::vector<module_snapshot> enumerate_process_modules(PEPROCESS process)
    {
        cstd::vector<module_snapshot> result;

        const auto* process_peb = LIMPORT(PsGetProcessPeb)(process);

        if (!process_peb)
        {
            return result;
        }

        KAPC_STATE apc_state{};
        LIMPORT(KeStackAttachProcess)(process, &apc_state);

        __try
        {
            const auto* peb_ptr = reinterpret_cast<const peb*>(process_peb);
            const auto* ldr = peb_ptr->ldr;

            if (!ldr)
            {
                LIMPORT(KeUnstackDetachProcess)(&apc_state);
                return result;
            }

            const auto* head = &ldr->in_load_order_module_list;
            const auto* current = head->Flink;

            while (current != head)
            {
                const auto* entry = CONTAINING_RECORD(current, ldr_data_table_entry, in_load_order_links);

                if (entry->dll_base && entry->size_of_image > 0)
                {
                    module_snapshot snap{};
                    snap.base_address = reinterpret_cast<uint64_t>(entry->dll_base);
                    snap.size_of_image = entry->size_of_image;

                    if (entry->base_dll_name.Buffer && entry->base_dll_name.Length > 0)
                    {
                        snap.name = cstd::to_string(cstd::wstring_view(
                            entry->base_dll_name.Buffer,
                            entry->base_dll_name.Length / sizeof(wchar_t)
                        ));
                    }

                    if (entry->full_dll_name.Buffer && entry->full_dll_name.Length > 0)
                    {
                        snap.full_path = cstd::to_string(cstd::wstring_view(
                            entry->full_dll_name.Buffer,
                            entry->full_dll_name.Length / sizeof(wchar_t)
                        ));
                    }

                    __try
                    {
                        auto* image = static_cast<portable_executable::image_t*>(entry->dll_base);

                        snap.hash = krnl::hash_nonwritable_sections(image);
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER)
                    {
                        DBG_LOG("exception reading PE for %s: 0x%x\n",
                            snap.name.data(), GetExceptionCode());
                        snap.hash = cstd::unexpected(nt_status(GetExceptionCode()));
                    }

                    result.push_back(cstd::move(snap));
                }

                current = current->Flink;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            DBG_LOG("exception walking PEB for process: 0x%x\n", GetExceptionCode());
        }

        LIMPORT(KeUnstackDetachProcess)(&apc_state);

        return result;
    }
}

namespace proc
{
    cstd::vector<uint8_t> get_protected_process_modules()
    {
        DBG_LOG("get_protected_process_modules: entering\n");

        flatbuffers::FlatBufferBuilder fbb;

        auto processes_vec = serialisation::collect<Anticheat::ProtectedProcess>(fbb, protected_process::all(),
            [](auto& b, const auto& proc)
            {
                const auto pid = static_cast<uint32_t>(proc.id());

                PEPROCESS process = nullptr;
                const auto status = LIMPORT(PsLookupProcessByProcessId)(
                    reinterpret_cast<HANDLE>(static_cast<uintptr_t>(pid)), &process
                );

                if (!nt_status(status) || !process)
                {
                    DBG_LOG("failed to lookup process %u: 0x%x\n", pid, status);
                    auto empty_modules = b.CreateVector(
                        static_cast<flatbuffers::Offset<Anticheat::ProcessModule>*>(nullptr), 0
                    );
                    return Anticheat::CreateProtectedProcess(b, pid, empty_modules);
                }

                auto snapshots = enumerate_process_modules(process);
                LIMPORT(ObDereferenceObject)(process);

                auto modules_vec = serialisation::collect<Anticheat::ProcessModule>(b, snapshots,
                    [](auto& b2, const auto& mod)
                    {
                        auto name_offset = b2.CreateString(mod.name.data(), mod.name.size());
                        auto path_offset = b2.CreateString(mod.full_path.data(), mod.full_path.size());

                        flatbuffers::Offset<flatbuffers::Vector<uint8_t>> hash_offset;

                        if (mod.hash)
                        {
                            hash_offset = b2.CreateVector(
                                mod.hash.value().data(), crypto::sha256_size
                            );
                        }
                        else
                        {
                            DBG_LOG("hash failed for user module %s: 0x%x\n",
                                mod.name.data(), mod.hash.error().value());
                        }

                        return Anticheat::CreateProcessModule(
                            b2,
                            mod.base_address,
                            mod.size_of_image,
                            name_offset,
                            hash_offset,
                            path_offset
                        );
                    });

                return Anticheat::CreateProtectedProcess(b, pid, modules_vec);
            });

        auto result = serialisation::serialise(fbb, serialisation::lift<Anticheat::CreateProtectedProcessList>(), processes_vec);

        DBG_LOG("protected process list: %zu bytes\n", result.size());

        return result;
    }
}
