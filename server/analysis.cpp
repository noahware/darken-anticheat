#include "analysis.hpp"
#include "log.hpp"

#include <schema/nmi_result_generated.h>

#include <ranges>
#include <format>
#include <span>
#include <algorithm>

namespace analysis
{
    static std::string to_hex(std::span<const std::uint8_t> bytes)
    {
        std::string result;
        result.reserve(bytes.size() * 2);

        for (const auto b : bytes)
        {
            result += std::format("{:02x}", b);
        }

        return result;
    }

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
                const auto* hash_vec = mod->hash();

                incoming.push_back({
                    mod->base_address(),
                    mod->size(),
                    mod->name() ? mod->name()->str() : "",
                    hash_vec ? std::vector<std::uint8_t>(hash_vec->begin(), hash_vec->end())
                             : std::vector<std::uint8_t>{}
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

            for (const auto& old_mod : modules)
            {
                const auto it = std::ranges::find(incoming, old_mod.base_address, &module_entry::base_address);

                if (it != incoming.end() && it->hash != old_mod.hash)
                {
                    LOG_WARN("module integrity mismatch: {} @ 0x{:x} (hash: {} -> {})",
                        old_mod.name, old_mod.base_address, to_hex(old_mod.hash), to_hex(it->hash));
                }
            }
        }
        else
        {
            LOG_INFO("initial kernel module list: {} modules", incoming.size());
        }

        modules = std::move(incoming);
    }

    static bool is_address_backed(std::uint64_t address, const std::vector<module_entry>& modules)
    {
        return std::ranges::any_of(modules, [address](const module_entry& mod)
        {
            return address >= mod.base_address && address < mod.base_address + mod.size;
        });
    }

    void process_thread_list(std::vector<thread_entry>& threads, const std::vector<module_entry>& modules, const Anticheat::ThreadList* list)
    {
        if (!list)
        {
            LOG_ERR("null ThreadList");
            return;
        }

        std::vector<thread_entry> incoming;

        if (const auto* fb_threads = list->threads())
        {
            incoming.reserve(fb_threads->size());

            for (const auto* t : *fb_threads)
            {
                incoming.push_back({ t->thread_id(), t->start_address() });
            }
        }

        if (!threads.empty())
        {
            for (const auto& old_thread : threads)
            {
                if (!std::ranges::contains(incoming, old_thread.thread_id, &thread_entry::thread_id))
                {
                    LOG_INFO("system thread exited: tid={}, start=0x{:x}",
                        old_thread.thread_id, old_thread.start_address);
                }
            }

            for (const auto& new_thread : incoming)
            {
                if (!std::ranges::contains(threads, new_thread.thread_id, &thread_entry::thread_id))
                {
                    LOG_INFO("system thread created: tid={}, start=0x{:x}",
                        new_thread.thread_id, new_thread.start_address);

                    if (!modules.empty() && !is_address_backed(new_thread.start_address, modules))
                    {
                        LOG_WARN("system thread start address 0x{:x} (tid={}) not backed by any loaded module",
                            new_thread.start_address, new_thread.thread_id);
                    }
                }
            }
        }
        else
        {
            LOG_INFO("initial thread list: {} system threads", incoming.size());

            if (!modules.empty())
            {
                for (const auto& t : incoming)
                {
                    if (!is_address_backed(t.start_address, modules))
                    {
                        LOG_WARN("system thread start address 0x{:x} (tid={}) not backed by any loaded module",
                            t.start_address, t.thread_id);
                    }
                }
            }
        }

        threads = std::move(incoming);
    }

    void process_nmi_result(const std::vector<module_entry>& modules, const Anticheat::NmiResult* result)
    {
        if (!result)
        {
            LOG_ERR("null NmiResult");
            return;
        }

        const auto* captures = result->captures();

        if (!captures || captures->size() == 0)
        {
            LOG_WARN("nmi result: empty captures");
            return;
        }

        const auto current_core = result->current_core();

        LOG_INFO("nmi result: {} cores, dispatcher core: {}", captures->size(), current_core);

        for (uint32_t i = 0; i < captures->size(); ++i)
        {
            const auto* cap = captures->Get(i);

            if (i == current_core)
            {
                continue;
            }

            if (!cap->processed())
            {
                LOG_WARN("nmi: core {} did not process callback", i);
                continue;
            }

            if ((cap->cs() & 3) != 0)
            {
                continue;
            }

            if (!modules.empty() && !is_address_backed(cap->rip(), modules))
            {
                LOG_WARN("nmi: core {} executing unbacked code at 0x{:x}", i, cap->rip());
            }
        }
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

            const auto* hash_vec = load->hash();

            modules.push_back({
                load->base_address(),
                load->size(),
                load->name() ? load->name()->str() : "",
                hash_vec ? std::vector<std::uint8_t>(hash_vec->begin(), hash_vec->end())
                         : std::vector<std::uint8_t>{}
            });

            LOG_INFO("module loaded: {} @ 0x{:x} (size: 0x{:x})",
                load->name() ? load->name()->c_str() : "unknown",
                load->base_address(), load->size());
        }
    }
}
