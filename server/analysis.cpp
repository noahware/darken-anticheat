#include "analysis.hpp"
#include "log.hpp"

#include <ranges>

namespace analysis
{
    void process_example_check(const Anticheat::ExampleCheckResult* result)
    {
        if (!result)
        {
            LOG_ERR("null ExampleCheckResult");
            return;
        }

        LOG_INFO("example check result: value=0x{:x}, status={}",
            result->value(), result->status());

        if (result->value() != 0x123)
        {
            LOG_WARN("unexpected example check value: 0x{:x} (expected 0x123)",
                result->value());
        }

        if (result->status() != 0)
        {
            LOG_WARN("example check status non-zero: {}", result->status());
        }
    }

    void process_client_timestamp(const Anticheat::ClientTimestampResult* result)
    {
        if (!result)
        {
            LOG_ERR("null ClientTimestampResult");
            return;
        }

        LOG_INFO("client timestamp: {}ms", result->timestamp());
    }

    void process_kernel_module_list(std::vector<module_entry>& modules, const Anticheat::KernelModuleList* list)
    {
        if (!list)
        {
            LOG_ERR("null KernelModuleList");
            return;
        }

        std::vector<module_entry> incoming;

        if (const auto* fb_modules = list->modules())
        {
            incoming.reserve(fb_modules->size());

            for (const auto* mod : *fb_modules)
            {
                incoming.push_back({
                    mod->base_address(),
                    mod->size(),
                    mod->name() ? mod->name()->str() : ""
                });
            }
        }

        if (!modules.empty())
        {
            for (const auto& old_mod : modules)
            {
                if (!std::ranges::contains(incoming, old_mod.base_address, &module_entry::base_address))
                {
                    LOG_INFO("module unloaded: {} @ 0x{:x} (size: 0x{:x})",
                        old_mod.name, old_mod.base_address, old_mod.size);
                }
            }

            for (const auto& new_mod : incoming)
            {
                if (!std::ranges::contains(modules, new_mod.base_address, &module_entry::base_address))
                {
                    LOG_INFO("module loaded: {} @ 0x{:x} (size: 0x{:x})",
                        new_mod.name, new_mod.base_address, new_mod.size);
                }
            }
        }
        else
        {
            LOG_INFO("initial kernel module list: {} modules", incoming.size());
        }

        modules = std::move(incoming);
    }

    void process_event_batch(std::vector<module_entry>& modules, const Anticheat::EventBatch* batch)
    {
        if (!batch)
        {
            LOG_ERR("null EventBatch");
            return;
        }

        const auto* events = batch->events();

        if (!events)
        {
            return;
        }

        for (const auto* event : *events)
        {
            if (event->body_type() != Anticheat::EventBody_KernelModuleLoad)
            {
                LOG_WARN("unknown event body type: {}", static_cast<int>(event->body_type()));
                continue;
            }

            const auto* load = event->body_as_KernelModuleLoad();

            if (!load)
            {
                continue;
            }

            modules.push_back({
                load->base_address(),
                load->size(),
                load->name() ? load->name()->str() : ""
            });

            LOG_INFO("module loaded: {} @ 0x{:x} (size: 0x{:x})",
                load->name() ? load->name()->c_str() : "unknown",
                load->base_address(), load->size());
        }
    }
}
