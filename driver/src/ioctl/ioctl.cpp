#include "ioctl.hpp"
#include "../events/events.hpp"
#include "../krnl/modules.hpp"
#include "../krnl/threads.hpp"
#include "../nmi/nmi.hpp"
#include "../state/protected_process.hpp"
#include "../log.hpp"
#include "../util/import.hpp"
#include "../handle/table.hpp"
#include "../mem/data_page_exec.hpp"
#include "../msr/msr.hpp"
#include "../process/process_modules.hpp"
#include "response_generated.h"
#include <driver/ioctl.h>

static nt_status complete_request(PIRP irp, const nt_status status, const ULONG_PTR information = 0)
{
    irp->IoStatus.Status = status;
    irp->IoStatus.Information = information;
    LIMPORT(IoCompleteRequest)(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS ioctl::dispatch([[maybe_unused]] PDEVICE_OBJECT device, PIRP irp)
{
    const auto* stack = LIMPORT(IoGetCurrentIrpStackLocation)(irp);
    const auto io_control_code = stack->Parameters.DeviceIoControl.IoControlCode;

    if (io_control_code == IOCTL_DARKEN_EVENT_HANDLE)
    {
        return events::get_event_handle(irp);
    }

    if (io_control_code == IOCTL_DARKEN_EVENT_DRAIN)
    {
        return events::drain(irp);
    }

    if (io_control_code == IOCTL_DARKEN_PROTECT_SELF)
    {
        const auto pid = reinterpret_cast<uint64_t>(LIMPORT(PsGetCurrentProcessId)());
        protected_process::add(pid);
        DBG_LOG("protected process: %llu\n", pid);
        return complete_request(irp, nt_status::success());
    }

    if (io_control_code != IOCTL_DARKEN_FBS_REQUEST)
    {
        return complete_request(irp, nt_status::invalid_device_request());
    }

    const auto input_size = stack->Parameters.DeviceIoControl.InputBufferLength;
    const auto output_capacity = stack->Parameters.DeviceIoControl.OutputBufferLength;
    auto* system_buffer = irp->AssociatedIrp.SystemBuffer;

    if (!system_buffer || input_size < sizeof(std::uint8_t))
    {
        return complete_request(irp, nt_status::invalid_parameter());
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

    case Anticheat::ResponseId_HandleStripCheck:
        response_bytes = handle::tbl::strip();
        break;

    case Anticheat::ResponseId_ReservedMsrCheck:
        response_bytes = msr::test_reserved();
        break;

    case Anticheat::ResponseId_ProtectedProcessList:
        response_bytes = proc::get_protected_process_modules();
        break;

    case Anticheat::ResponseId_KernelDataPageExecCheck:
        response_bytes = mem::data_page_exec_check();
        break;

    default:
        DBG_LOG("unknown request id: %d\n", static_cast<int>(request_id));
        return complete_request(irp, nt_status::invalid_parameter());
    }

    if (response_bytes.size() > output_capacity)
    {
        return complete_request(irp, nt_status::buffer_too_small());
    }

    cstd::crt::memcpy(system_buffer, response_bytes.data(), response_bytes.size());

    return complete_request(irp, nt_status::success(), response_bytes.size());
}
