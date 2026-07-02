#pragma once
#include <schema/client_timestamp_generated.h>
#include <schema/kernel_modules_generated.h>
#include <schema/handle_strip_generated.h>
#include <schema/event_generated.h>
#include <schema/thread_generated.h>
#include <schema/nmi_result_generated.h>
#include <schema/kernel_data_page_exec_result_generated.h>
#include <schema/reserved_msr_result_generated.h>
#include <schema/protected_process_generated.h>

#include <portable_executable/section_header.hpp>

#include <chrono>
#include <cstdint>
#include <mutex>
#include <span>
#include <string>
#include <unordered_set>
#include <vector>

class client_connection;

namespace analysis
{
    struct section_entry
    {
        std::string name;
        std::uint32_t virtual_address;
        std::uint32_t virtual_size;
        portable_executable::section_characteristics_t characteristics;

        [[nodiscard]] bool is_discardable() const noexcept
        {
            return characteristics.mem_discardable;
        }
    };

    struct module_entry
    {
        std::uint64_t base_address;
        std::uint32_t size;
        std::string name;
        std::vector<std::uint8_t> hash;
        std::string full_path;
        std::string rwx_section;
        std::vector<section_entry> sections;
        std::chrono::steady_clock::time_point load_time;

        [[nodiscard]] bool discardable_allowed() const noexcept
        {
            constexpr auto grace_period = std::chrono::seconds(5);
            return std::chrono::steady_clock::now() - load_time < grace_period;
        }
    };

    struct process_entry
    {
        std::uint32_t process_id;
        std::vector<module_entry> modules;
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
    void process_kernel_module_list(client_connection& conn, std::vector<module_entry>& modules, const Anticheat::KernelModuleList* list);
    void process_event_batch(client_connection& conn, std::vector<module_entry>& modules, std::vector<process_entry>& processes, const Anticheat::EventBatch* batch);
    void process_thread_list(std::vector<thread_entry>& threads, std::span<const module_entry> modules, const Anticheat::ThreadList* list);
    void process_nmi_result(std::span<const module_entry> modules, std::span<const process_entry> processes, const Anticheat::NmiResult* result);
    void process_handle_strip_result(const Anticheat::HandleStripResult* result);
    void process_reserved_msr_result(const Anticheat::ReservedMsrResult* result);
    void process_protected_process_list(std::vector<process_entry>& processes, const Anticheat::ProtectedProcessList* list);
    void process_kernel_data_page_exec_check_result(std::span<const module_entry> modules, const Anticheat::KernelDataPageExecCheckResult* list);

    std::vector<std::string> find_unsigned_modules(std::span<const module_entry> modules);
}
