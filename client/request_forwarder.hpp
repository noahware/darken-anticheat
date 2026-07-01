#pragma once
#include "driver.hpp"
#include "log.hpp"

#include <connection/session.hpp>
#include <message/message.hpp>

#include <span>
#include <thread>

namespace request
{
    template <std::uint8_t DriverCheckId, std::uint8_t ServerResultId>
    bool send_from_driver(const std::shared_ptr<sl::session>& sess)
    {
        auto result = driver::run_check(DriverCheckId);

        if (!result)
        {
            LOG_ERR("driver request failed for check {}", DriverCheckId);
            return false;
        }

        auto data = std::make_shared<std::vector<std::uint8_t>>(std::move(*result));

        sl::msg::async_send_view(
            sess->socket(), ServerResultId,
            [data](bool) {},
            std::span<const std::uint8_t>{data->data(), data->size()}
        );

        LOG_INFO("forwarded check {} ({} bytes)", DriverCheckId, data->size());
        return true;
    }

    template <std::uint8_t DriverCheckId, std::uint8_t ServerResultId, class RequestType>
    void forward(const std::shared_ptr<sl::session>& sess, [[maybe_unused]] const RequestType*)
    {
        auto session = sess;
        std::thread([session]()
        {
            send_from_driver<DriverCheckId, ServerResultId>(session);
        }).detach();
    }
}
