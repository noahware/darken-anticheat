#pragma once
#include "../krnl/nt_status.hpp"

namespace handle::tbl
{
    nt_status init();
    void strip();
}
