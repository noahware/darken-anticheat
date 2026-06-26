#include "analysis.hpp"
#include "log.hpp"

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

        modules.clear();

        if (const auto* fb_modules = list->modules())
        {
            modules.reserve(fb_modules->size());

            for (const auto* mod : *fb_modules)
            {
                modules.push_back({
                    mod->base_address(),
                    mod->size(),
                    mod->name() ? mod->name()->str() : ""
                });
            }
        }

        LOG_INFO("kernel module list updated: {} modules", modules.size());
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
