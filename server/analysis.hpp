#pragma once
#include <schema/client_timestamp_generated.h>
#include <schema/kernel_modules_generated.h>
#include <schema/handle_strip_generated.h>
#include <schema/event_generated.h>
#include <schema/thread_generated.h>
#include <schema/nmi_result_generated.h>

#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>
#include <schema/reserved_msr_result_generated.h>

namespace analysis
{
    struct module_entry
    {
        std::uint64_t base_address;
        std::uint32_t size;
        std::string name;
        std::vector<std::uint8_t> hash;
        std::string full_path;
    };

    struct thread_entry
    {
        std::uint32_t thread_id;
        std::uint64_t start_address;
    };

    inline std::unordered_set<std::string> verified_hashes;
    inline std::mutex verified_hashes_mutex;

    std::string to_hex(std::span<const std::uint8_t> bytes);

    void process_client_timestamp(const Anticheat::ClientTimestampResult* result);
    void process_kernel_module_list(std::vector<module_entry>& modules, const Anticheat::KernelModuleList* list);
    void process_event_batch(std::vector<module_entry>& modules, const Anticheat::EventBatch* batch);
    void process_thread_list(std::vector<thread_entry>& threads, const std::vector<module_entry>& modules, const Anticheat::ThreadList* list);
    void process_nmi_result(const std::vector<module_entry>& modules, const Anticheat::NmiResult* result);
    void process_handle_strip_result(const Anticheat::HandleStripResult* result);
    void process_reserved_msr_result(const Anticheat::ReservedMsrResult* result);

    std::vector<std::string> find_unsigned_modules(std::span<const module_entry> modules);
}
