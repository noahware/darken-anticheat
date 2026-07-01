#pragma once
#include <vector.hpp>

namespace proc
{
    [[nodiscard]] cstd::vector<uint8_t> get_protected_process_modules();
}
