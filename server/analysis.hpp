#pragma once
#include <schema/example_check_generated.h>
#include <schema/client_timestamp_generated.h>
#include <schema/kernel_modules_generated.h>
#include <schema/event_generated.h>

#include <cstdint>
#include <string>
#include <vector>

namespace analysis
{
    struct module_entry
    {
        std::uint64_t base_address;
        std::uint32_t size;
        std::string name;
        std::uint64_t hash;
    };

    void process_example_check(const Anticheat::ExampleCheckResult* result);
    void process_client_timestamp(const Anticheat::ClientTimestampResult* result);
    void process_kernel_module_list(std::vector<module_entry>& modules, const Anticheat::KernelModuleList* list);
    void process_event_batch(std::vector<module_entry>& modules, const Anticheat::EventBatch* batch);
}
