#pragma once
#include <cstdint>
#include <optional>
#include <vector>

namespace driver
{
    bool open();
    bool is_open();
    void close();

    std::optional<std::vector<std::uint8_t>> run_check(std::uint8_t check_id);
}
