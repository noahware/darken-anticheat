#pragma once
#include <connection/session.hpp>
#include <schema/response_generated.h>

namespace handlers
{
    void handle_pong(const std::shared_ptr<sl::session>& sess, const Anticheat::PongResponse* pong);
    void handle_example_check(const std::shared_ptr<sl::session>& sess, const Anticheat::ExampleCheckRequest* request);
    void handle_client_timestamp(const std::shared_ptr<sl::session>& sess, const Anticheat::ClientTimestampRequest* request);
}
