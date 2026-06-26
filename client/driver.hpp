#pragma once
#include <cstdint>
#include <optional>
#include <vector>

namespace driver
{
    bool open();
    bool is_open();
    void cancel_io();
    void close();

    std::optional<std::vector<std::uint8_t>> run_check(std::uint8_t check_id);
    std::optional<std::vector<std::uint8_t>> get_module_list();
    std::optional<void*> get_event_handle();
    std::optional<std::vector<std::uint8_t>> drain_events();
}
