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

        flatbuffers::FlatBufferBuilder fbb(2048);
        cstd::vector<flatbuffers::Offset<Anticheat::Thread>> thread_offsets;

        auto* entry = reinterpret_cast<system_process_information*>(buffer.data());

        for (;;)
        {
            if (entry->unique_process_id == reinterpret_cast<HANDLE>(4))
            {
                for (ULONG i = 0; i < entry->number_of_threads; ++i)
                {
                    const auto& thread = entry->threads[i];
                    const auto tid = static_cast<uint32_t>(
                        reinterpret_cast<uintptr_t>(thread.client_id.UniqueThread)
                    );
                    const auto start = reinterpret_cast<uint64_t>(thread.start_address);

                    thread_offsets.push_back(
                        Anticheat::CreateThread(fbb, tid, start)
                    );
                }

                break;
            }

            if (entry->next_entry_offset == 0)
            {
                break;
            }

            entry = reinterpret_cast<system_process_information*>(
                reinterpret_cast<uint8_t*>(entry) + entry->next_entry_offset
            );
        }

        auto threads_vec = fbb.CreateVector(thread_offsets.data(), thread_offsets.size());
        auto result = serialisation::serialise(fbb, serialisation::lift<Anticheat::CreateThreadList>(), threads_vec);

        DBG_LOG("thread list: %zu threads, %zu bytes\n", thread_offsets.size(), result.size());

        return result;
    }
}
