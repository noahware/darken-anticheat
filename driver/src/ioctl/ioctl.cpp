#include "ioctl.hpp"

#include "../events/events.hpp"
#include "../krnl/modules.hpp"
#include "../krnl/threads.hpp"
#include "../nmi/nmi.hpp"
#include "../log.hpp"
#include <driver/ioctl.h>
#include "response_generated.h"

static NTSTATUS complete_request(PIRP irp, const NTSTATUS status, const ULONG_PTR information = 0)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS ioctl::dispatch([[maybe_unused]] PDEVICE_OBJECT device, PIRP irp)
{
    const auto* stack = IoGetCurrentIrpStackLocation(irp);
    const auto io_control_code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (io_control_code == IOCTL_DARKEN_EVENT_HANDLE)
    {
        return events::get_event_handle(irp);
    }

    if (io_control_code == IOCTL_DARKEN_EVENT_DRAIN)
    {
        return events::drain(irp);
    }

    if (io_control_code != IOCTL_DARKEN_FBS_REQUEST)
    {
        return complete_request(irp, STATUS_INVALID_DEVICE_REQUEST);
    }

    const auto input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
    const auto output_capacity = stack->Parameters.DeviceIoControl.OutputBufferLength;
    auto* system_buffer = irp->AssociatedIrp.SystemBuffer;

    if (!system_buffer || input_size < sizeof(std::uint8_t))
    {
        return complete_request(irp, STATUS_INVALID_PARAMETER);
    }

    const auto request_id = static_cast<Anticheat::ResponseId>(*static_cast<const std::uint8_t*>(system_buffer));
    cstd::vector<uint8_t> response_bytes;

    switch (request_id)
    {
    case Anticheat::ResponseId_KernelModuleList:
        response_bytes = krnl::get_module_list();
        break;

    case Anticheat::ResponseId_ThreadList:
        response_bytes = krnl::get_thread_list();
        break;

    case Anticheat::ResponseId_NmiCheck:
        response_bytes = nmi::capture_rips();
        break;

    default:
        DBG_LOG("unknown request id: %d\n", static_cast<int>(request_id));
        return complete_request(irp, STATUS_INVALID_PARAMETER);
    }

    if (response_bytes.size() > output_capacity)
    {
        return complete_request(irp, STATUS_BUFFER_TOO_SMALL);
    }

    cstd::crt::memcpy(system_buffer, response_bytes.data(), response_bytes.size());

    return complete_request(irp, STATUS_SUCCESS, response_bytes.size());
}
