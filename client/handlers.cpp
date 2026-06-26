#include "handlers.hpp"
#include "driver.hpp"
#include "log.hpp"

#include <message/message.hpp>
#include <schema/request_generated.h>
#include <schema/client_timestamp_generated.h>

#include <chrono>

namespace handlers
{
    void handle_pong(
        [[maybe_unused]] const std::shared_ptr<sl::session>& sess,
        const Anticheat::PongResponse* pong)
    {
        LOG_INFO("pong (server_timestamp: {})", pong->server_timestamp());
    }

    void handle_example_check(
        const std::shared_ptr<sl::session>& sess,
        [[maybe_unused]] const Anticheat::ExampleCheckRequest* request)
    {
        LOG_INFO("received example check request");

        auto driver_result = driver::run_check(Anticheat::ResponseId_ExampleCheck);

        if (!driver_result)
        {
            LOG_ERR("driver request failed for ExampleCheck");
            return;
        }

        auto data = std::make_shared<std::vector<std::uint8_t>>(std::move(*driver_result));

        sl::msg::async_send_view(
            sess->socket(), Anticheat::RequestId_ExampleCheckResult,
            [data](bool) {},
            std::span<const std::uint8_t>{data->data(), data->size()}
        );

        LOG_INFO("sent example check result (size: {})", data->size());
    }

    void handle_client_timestamp(
        const std::shared_ptr<sl::session>& sess,
        [[maybe_unused]] const Anticheat::ClientTimestampRequest* request)
    {
        LOG_INFO("received client timestamp request");

        const auto now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );

        sl::msg::async_send<Anticheat::CreateClientTimestampResult>(
            sess->socket(), Anticheat::RequestId_ClientTimestampResult,
            now
        );

        LOG_INFO("sent client timestamp: {}ms", now);
    }
}
