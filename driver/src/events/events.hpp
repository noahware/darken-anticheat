#pragma once
#include <ntifs.h>

namespace events
{
    NTSTATUS init();
    void cleanup();

    NTSTATUS get_event_handle(PIRP irp);
    NTSTATUS drain(PIRP irp);
}
