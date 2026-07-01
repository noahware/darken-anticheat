#include "client_session.hpp"
#include "handlers.hpp"
#include "request_forwarder.hpp"
#include "log.hpp"

#include <router/router.hpp>
#include <schema/request_generated.h>
#include <schema/response_generated.h>
#include <schema/signature_generated.h>

namespace
{
    constexpr sl::message_info<Anticheat::PongResponse, sl::session> pong_response{
        Anticheat::ResponseId_Pong, handlers::handle_pong
    };

    constexpr sl::message_info<Anticheat::ClientTimestampRequest, sl::session> client_timestamp_request{
        Anticheat::ResponseId_ClientTimestamp, handlers::handle_client_timestamp
    };

    constexpr sl::message_info<Anticheat::ImageSignatureCheckRequest, sl::session> image_signature_check_request{
        Anticheat::ResponseId_ImageSignatureCheck, handlers::handle_image_signature_check
    };

    // driver-backed checks: server requests check, client forwards driver response
    // to add a new one, add a line here and the corresponding entry in the router below

    constexpr sl::message_info<Anticheat::KernelModuleListRequest, sl::session> kernel_module_list_request{
        Anticheat::ResponseId_KernelModuleList,
        request::forward<Anticheat::ResponseId_KernelModuleList, Anticheat::RequestId_KernelModuleListResult, Anticheat::KernelModuleListRequest>
    };

    constexpr sl::message_info<Anticheat::ThreadListRequest, sl::session> thread_list_request{
        Anticheat::ResponseId_ThreadList,
        request::forward<Anticheat::ResponseId_ThreadList, Anticheat::RequestId_ThreadListResult, Anticheat::ThreadListRequest>
    };

    constexpr sl::message_info<Anticheat::NmiCheckRequest, sl::session> nmi_check_request{
        Anticheat::ResponseId_NmiCheck,
        request::forward<Anticheat::ResponseId_NmiCheck, Anticheat::RequestId_NmiResultData, Anticheat::NmiCheckRequest>
    };

    constexpr sl::message_info<Anticheat::HandleStripCheckRequest, sl::session> handle_strip_check_request{
        Anticheat::ResponseId_HandleStripCheck,
        request::forward<Anticheat::ResponseId_HandleStripCheck, Anticheat::RequestId_HandleStripData, Anticheat::HandleStripCheckRequest>
    };

    constexpr sl::message_info<Anticheat::ReservedMsrCheckRequest, sl::session> reserved_msr_check_request{
	    Anticheat::ResponseId_ReservedMsrCheck,
	    request::forward<Anticheat::ResponseId_ReservedMsrCheck, Anticheat::RequestId_ReservedMsrData, Anticheat::ReservedMsrCheckRequest>
    };

    constexpr sl::message_info<Anticheat::ProtectedProcessListRequest, sl::session> protected_process_list_request{
        Anticheat::ResponseId_ProtectedProcessList,
        request::forward<Anticheat::ResponseId_ProtectedProcessList, Anticheat::RequestId_ProtectedProcessListResult, Anticheat::ProtectedProcessListRequest>
    };

    using response_router = sl::message_router<pong_response, client_timestamp_request, kernel_module_list_request, thread_list_request, nmi_check_request, image_signature_check_request, handle_strip_check_request, reserved_msr_check_request, protected_process_list_request>;
}

void client_session::handle_message(const message_id_t id, const body_buffer_t body)
{
    if (!response_router::dispatch(id, shared_as<sl::session>(), *body))
    {
        LOG_ERR("unknown response type: {}", id);
    }
}

void client_session::on_error()
{
    LOG_ERR("disconnected from server");
    stop();
}
