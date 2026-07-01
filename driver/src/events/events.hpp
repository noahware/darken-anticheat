#pragma once
#include <ntifs.h>

#include "../krnl/nt_status.hpp"

namespace events
{
    nt_status init();
    void cleanup();

    nt_status get_event_handle(PIRP irp);
    nt_status drain(PIRP irp);
}
