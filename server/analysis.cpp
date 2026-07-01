#include "analysis.hpp"
#include "log.hpp"

#include <schema/nmi_result_generated.h>

#include <ranges>
#include <format>
#include <span>
#include <algorithm>

namespace analysis
{
    std::string to_hex(std::span<const std::uint8_t> bytes)
    {
        std::string result;
        result.reserve(bytes.size() * 2);

        for (const auto b : bytes)
        {
            result += std::format("{:02x}", b);
        }

        return result;
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
                             : std::vector<std::uint8_t>{},
                    mod->full_path() ? mod->full_path()->str() : ""
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

    void process_handle_strip_result(const Anticheat::HandleStripResult* result)
    {
	    if (!result)
	    {
            LOG_ERR("null HandleStripResult");

            return;
	    }

        const auto* handles = result->handles();

        if (!handles)
        {
            return;
        }

        for (const auto* handle : *handles)
        {
            LOG_WARN("process ID 0x{:X} had its handle stripped (access: 0x{:X}, target protected process id: 0x{:X})",
                     handle->source_process_id(), handle->access(), handle->target_process_id());
        }
    }

    void process_reserved_msr_result(const Anticheat::ReservedMsrResult* result)
    {
	    if (!result)
	    {
            LOG_ERR("null ReservedMsr");
            return;
	    }

        if (const auto msr = result->non_throwing_msr())
        {
            LOG_INFO("reserved MSR 0x{:X} is being used", msr.value());
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
                         : std::vector<std::uint8_t>{},
                load->full_path() ? load->full_path()->str() : ""
            });

            LOG_INFO("module loaded: {} @ 0x{:x} (size: 0x{:x})",
                load->name() ? load->name()->c_str() : "unknown",
                load->base_address(), load->size());
        }
    }

    static void diff_module_list(
        const std::uint32_t pid,
        const std::vector<module_entry>& old_modules,
        const std::vector<module_entry>& new_modules)
    {
        for (const auto& old_mod : old_modules)
        {
            if (!std::ranges::contains(new_modules, old_mod.base_address, &module_entry::base_address))
            {
                LOG_INFO("[pid 0x{:x}] module unloaded: {} @ 0x{:x}", pid, old_mod.name, old_mod.base_address);
            }
        }

        for (const auto& new_mod : new_modules)
        {
            if (!std::ranges::contains(old_modules, new_mod.base_address, &module_entry::base_address))
            {
                LOG_INFO("[pid 0x{:x}] module loaded: {} @ 0x{:x} (size: 0x{:x})", pid, new_mod.name, new_mod.base_address, new_mod.size);
            }
        }

        for (const auto& old_mod : old_modules)
        {
            const auto it = std::ranges::find(new_modules, old_mod.base_address, &module_entry::base_address);

            if (it == new_modules.end())
            {
                continue;
            }

            if (it->hash != old_mod.hash)
            {
                LOG_WARN("[pid 0x{:x}] module integrity mismatch: {} @ 0x{:x} (hash: {} -> {})",
                    pid, old_mod.name, old_mod.base_address, to_hex(old_mod.hash), to_hex(it->hash));
            }
        }
    }

    static std::vector<module_entry> parse_process_modules(const Anticheat::ProtectedProcess* proc)
    {
        std::vector<module_entry> modules;

        const auto* fb_modules = proc->modules();

        if (!fb_modules)
        {
            return modules;
        }

        modules.reserve(fb_modules->size());

        for (const auto* mod : *fb_modules)
        {
            const auto* hash_vec = mod->hash();

            modules.push_back({
                mod->base_address(),
                mod->size(),
                mod->name() ? mod->name()->str() : "",
                hash_vec ? std::vector<std::uint8_t>(hash_vec->begin(), hash_vec->end())
                         : std::vector<std::uint8_t>{},
                mod->full_path() ? mod->full_path()->str() : ""
            });
        }

        return modules;
    }

    void process_protected_process_list(std::vector<process_entry>& processes, const Anticheat::ProtectedProcessList* list)
    {
        if (!list)
        {
            LOG_ERR("null ProtectedProcessList");
            return;
        }

        std::vector<process_entry> incoming;

        if (const auto* fb_processes = list->processes())
        {
            incoming.reserve(fb_processes->size());

            for (const auto* proc : *fb_processes)
            {
                incoming.push_back({
                    proc->process_id(),
                    parse_process_modules(proc)
                });
            }
        }

        if (!processes.empty())
        {
            for (const auto& old_proc : processes)
            {
                if (!std::ranges::contains(incoming, old_proc.process_id, &process_entry::process_id))
                {
                    LOG_INFO("protected process exited: pid 0x{:x}", old_proc.process_id);
                }
            }

            for (const auto& new_proc : incoming)
            {
                const auto it = std::ranges::find(processes, new_proc.process_id, &process_entry::process_id);

                if (it == processes.end())
                {
                    LOG_INFO("protected process appeared: pid 0x{:x} ({} modules)", new_proc.process_id, new_proc.modules.size());
                }
                else
                {
                    diff_module_list(new_proc.process_id, it->modules, new_proc.modules);
                }
            }
        }
        else if (!incoming.empty())
        {
            LOG_INFO("initial protected process list: {} processes", incoming.size());

            for (const auto& proc : incoming)
            {
                const auto empty_hashes = std::ranges::count_if(proc.modules,
                    [](const auto& m) { return m.hash.empty(); });

                LOG_INFO("  pid 0x{:x}: {} modules ({} without hash)", proc.process_id, proc.modules.size(), empty_hashes);
            }
        }

        processes = std::move(incoming);
    }

    std::vector<std::string> find_unsigned_modules(std::span<const module_entry> modules)
    {
        std::vector<std::string> paths;
        std::lock_guard lock(verified_hashes_mutex);

        for (const auto& mod : modules)
        {
            if (mod.hash.empty() || mod.full_path.empty())
            {
                continue;
            }

            const auto hex = to_hex(mod.hash);

            if (!verified_hashes.contains(hex))
            {
                paths.push_back(mod.full_path);
            }
        }

        return paths;
    }
}
