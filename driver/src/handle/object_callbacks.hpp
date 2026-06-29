#pragma once
#include "../krnl/nt_status.hpp"

namespace handle::ob_callbacks
{
    nt_status load();
    nt_status unload();
}
