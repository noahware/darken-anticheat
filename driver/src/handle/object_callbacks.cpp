#include "object_callbacks.hpp"
#include "../state/protected_process.hpp"
#include "../log.hpp"

#include <ntifs.h>

namespace
{
    void* registration_handle = nullptr;
}

#define PROCESS_QUERY_LIMITED_INFORMATION (0x1000)

static OB_PREOP_CALLBACK_STATUS pre_operation_callback([[maybe_unused]] void* const context,
                                                       const POB_PRE_OPERATION_INFORMATION info)
{
    const auto current_process = IoGetCurrentProcess();
    const auto target_process = static_cast<decltype(current_process)>(info->Object);

    if (target_process == current_process)
    {
        return OB_PREOP_SUCCESS;
    }

    const auto target_process_id = reinterpret_cast<protected_process_t::id_type>(PsGetProcessId(target_process));
    const auto* const protected_process = protected_process_t::find(target_process_id);

    if (!protected_process)
    {
        return OB_PREOP_SUCCESS;
    }

    const auto current_process_id = reinterpret_cast<protected_process_t::id_type>(PsGetProcessId(current_process));

    ACCESS_MASK* const desired_access = info->Operation == OB_OPERATION_HANDLE_CREATE
                                            ? &info->Parameters->CreateHandleInformation.DesiredAccess
                                            : &info->Parameters->DuplicateHandleInformation.DesiredAccess;

    DBG_LOG("process 0x%llx attempted to open handle to protected process 0x%llx (access=0x%lx)\n",
            current_process_id, target_process_id, *desired_access);

    *desired_access = SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION;

    return OB_PREOP_SUCCESS;
}

static void post_operation_callback([[maybe_unused]] void* const context,
                                    [[maybe_unused]] const POB_POST_OPERATION_INFORMATION info)
{
}

nt_status handle::cbs::load()
{
    POBJECT_TYPE* const process_type = PsProcessType;

    OB_OPERATION_REGISTRATION op_registration = {
        .ObjectType = process_type,
        .Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
        .PreOperation = pre_operation_callback,
        .PostOperation = post_operation_callback
    };

    OB_CALLBACK_REGISTRATION cb_registration = {
        .Version = OB_FLT_REGISTRATION_VERSION,
        .OperationRegistrationCount = 1,
        .Altitude = RTL_CONSTANT_STRING(L"371337"),
        .RegistrationContext = nullptr,
        .OperationRegistration = &op_registration
    };

    return ObRegisterCallbacks(&cb_registration, &registration_handle);
}

nt_status handle::cbs::unload()
{
    if (registration_handle)
    {
        ObUnRegisterCallbacks(registration_handle);
        registration_handle = nullptr;
    }

    return nt_status::success();
}
