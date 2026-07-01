#pragma once
#include <vector.hpp>

#include "../krnl/nt_status.hpp"

namespace handle::tbl
{
    nt_status init();
    [[nodiscard]] cstd::vector<uint8_t> strip();
}
