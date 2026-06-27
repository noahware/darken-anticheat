#pragma once
#include <connection/session.hpp>
#include <schema/response_generated.h>

namespace handlers
{
    void handle_pong(const std::shared_ptr<sl::session>& sess, const Anticheat::PongResponse* pong);
    void handle_example_check(const std::shared_ptr<sl::session>& sess, const Anticheat::ExampleCheckRequest* request);
    void handle_client_timestamp(const std::shared_ptr<sl::session>& sess, const Anticheat::ClientTimestampRequest* request);
    void handle_kernel_module_list_request(const std::shared_ptr<sl::session>& sess, const Anticheat::KernelModuleListRequest* request);
    bool send_kernel_module_list(const std::shared_ptr<sl::session>& sess);

    void handle_thread_list_request(const std::shared_ptr<sl::session>& sess, const Anticheat::ThreadListRequest* request);
    bool send_thread_list(const std::shared_ptr<sl::session>& sess);

    void handle_nmi_check_request(const std::shared_ptr<sl::session>& sess, const Anticheat::NmiCheckRequest* request);
    bool send_nmi_result(const std::shared_ptr<sl::session>& sess);
}
