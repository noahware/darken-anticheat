#pragma once
#include "../krnl/nt_status.hpp"

namespace handle::cbs
{
    nt_status load();
    nt_status unload();
}
