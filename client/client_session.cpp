#include "client_session.hpp"
#include "handlers.hpp"
#include "log.hpp"

#include <router/router.hpp>
#include <schema/response_generated.h>

namespace
{
    constexpr sl::message_info<Anticheat::PongResponse, sl::session> pong_response{
        Anticheat::ResponseId_Pong, handlers::handle_pong
    };

    constexpr sl::message_info<Anticheat::ExampleCheckRequest, sl::session> example_check_request{
        Anticheat::ResponseId_ExampleCheck, handlers::handle_example_check
    };

    constexpr sl::message_info<Anticheat::ClientTimestampRequest, sl::session> client_timestamp_request{
        Anticheat::ResponseId_ClientTimestamp, handlers::handle_client_timestamp
    };

    constexpr sl::message_info<Anticheat::KernelModuleListRequest, sl::session> kernel_module_list_request{
        Anticheat::ResponseId_KernelModuleList, handlers::handle_kernel_module_list_request
    };

    using response_router = sl::message_router<pong_response, example_check_request, client_timestamp_request, kernel_module_list_request>;
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
