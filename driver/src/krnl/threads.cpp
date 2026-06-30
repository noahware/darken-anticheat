#include "threads.hpp"
#include "types.hpp"
#include "nt_status.hpp"
#include "../log.hpp"
#include "../util/import.hpp"

#include "flatbuffers/flatbuffers.h"
#include "thread_generated.h"
#include "../util/serialisation.hpp"

namespace krnl
{
    constexpr ULONG system_process_info_class = 5;
    constexpr SIZE_T initial_buffer_size = 256 * 1024;
    constexpr SIZE_T max_buffer_size = 4 * 1024 * 1024;

    cstd::vector<uint8_t> get_thread_list()
    {
        DBG_LOG("get_thread_list: entering\n");

        cstd::vector<uint8_t> buffer(initial_buffer_size);
        ULONG return_length = 0;

        nt_status status = LIMPORT(ZwQuerySystemInformation)(
            system_process_info_class,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &return_length
        );

        while (status == nt_status::info_length_mismatch())
        {
            const auto new_size = buffer.size() * 2;

            if (new_size > max_buffer_size)
            {
                DBG_LOG("get_thread_list: buffer exceeds max size\n");
                return {};
            }

            buffer.resize(new_size);

            status = LIMPORT(ZwQuerySystemInformation)(
                system_process_info_class,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &return_length
            );
        }

        if (!status)
        {
            DBG_LOG("get_thread_list: ZwQuerySystemInformation failed: 0x%x\n", status.value());
            return {};
        }

        auto* entry = reinterpret_cast<system_process_information*>(buffer.data());

        while (entry->unique_process_id != reinterpret_cast<HANDLE>(4))
        {
            if (entry->next_entry_offset == 0)
            {
                DBG_LOG("get_thread_list: system process not found\n");
                return {};
            }

            entry = reinterpret_cast<system_process_information*>(
                reinterpret_cast<uint8_t*>(entry) + entry->next_entry_offset
            );
        }

        flatbuffers::FlatBufferBuilder fbb;
        const auto threads = cstd::span<SYSTEM_THREAD_INFORMATION>(entry->threads, entry->number_of_threads);

        auto threads_vec = serialisation::collect<Anticheat::Thread>(fbb, threads,
            [](auto& b, const auto& thread)
            {
                const auto tid = static_cast<uint32_t>(
                    reinterpret_cast<uintptr_t>(thread.client_id.UniqueThread)
                );
                const auto start = reinterpret_cast<uint64_t>(thread.start_address);

                return Anticheat::CreateThread(b, tid, start);
            });

        auto result = serialisation::serialise(fbb, serialisation::lift<Anticheat::CreateThreadList>(), threads_vec);

        DBG_LOG("thread list: %zu bytes\n", result.size());

        return result;
    }
}
