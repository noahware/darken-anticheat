#include "handlers.hpp"
#include "driver.hpp"
#include "log.hpp"

#include <message/message.hpp>
#include <schema/request_generated.h>
#include <schema/client_timestamp_generated.h>
#include <schema/response_generated.h>
#include <schema/kernel_modules_generated.h>
#include <schema/thread_generated.h>
#include <schema/nmi_result_generated.h>

#include <chrono>
#include <thread>

namespace handlers
{
    void handle_pong(
        [[maybe_unused]] const std::shared_ptr<sl::session>& sess,
        const Anticheat::PongResponse* pong)
    {
        LOG_INFO("pong (server_timestamp: {})", pong->server_timestamp());
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

    bool send_kernel_module_list(const std::shared_ptr<sl::session>& sess)
    {
        auto module_list = driver::get_module_list();

        if (!module_list)
        {
            LOG_ERR("driver request failed for KernelModuleList");
            return false;
        }

        auto data = std::make_shared<std::vector<std::uint8_t>>(std::move(*module_list));

        sl::msg::async_send_view(
            sess->socket(), Anticheat::RequestId_KernelModuleListResult,
            [data](bool) {},
            std::span<const std::uint8_t>{data->data(), data->size()}
        );

        LOG_INFO("sent kernel module list ({} bytes)", data->size());
        return true;
    }

    void handle_kernel_module_list_request(
        const std::shared_ptr<sl::session>& sess,
        [[maybe_unused]] const Anticheat::KernelModuleListRequest* request)
    {
        LOG_INFO("received kernel module list request");

        auto session = sess;
        std::thread([session]()
        {
            handlers::send_kernel_module_list(session);
        }).detach();
    }

    bool send_thread_list(const std::shared_ptr<sl::session>& sess)
    {
        auto thread_list = driver::get_thread_list();

        if (!thread_list)
        {
            LOG_ERR("driver request failed for ThreadList");
            return false;
        }

        auto data = std::make_shared<std::vector<std::uint8_t>>(std::move(*thread_list));

        sl::msg::async_send_view(
            sess->socket(), Anticheat::RequestId_ThreadListResult,
            [data](bool) {},
            std::span<const std::uint8_t>{data->data(), data->size()}
        );

        LOG_INFO("sent thread list ({} bytes)", data->size());
        return true;
    }

    void handle_thread_list_request(
        const std::shared_ptr<sl::session>& sess,
        [[maybe_unused]] const Anticheat::ThreadListRequest* request)
    {
        LOG_INFO("received thread list request");

        auto session = sess;
        std::thread([session]()
        {
            handlers::send_thread_list(session);
        }).detach();
    }

    bool send_nmi_result(const std::shared_ptr<sl::session>& sess)
    {
        auto nmi_data = driver::get_nmi_result();

        if (!nmi_data)
        {
            LOG_ERR("driver request failed for NmiCheck");
            return false;
        }

        auto data = std::make_shared<std::vector<std::uint8_t>>(std::move(*nmi_data));

        sl::msg::async_send_view(
            sess->socket(), Anticheat::RequestId_NmiResultData,
            [data](bool) {},
            std::span<const std::uint8_t>{data->data(), data->size()}
        );

        LOG_INFO("sent nmi result ({} bytes)", data->size());
        return true;
    }

    void handle_nmi_check_request(
        const std::shared_ptr<sl::session>& sess,
        [[maybe_unused]] const Anticheat::NmiCheckRequest* request)
    {
        LOG_INFO("received nmi check request");

        auto session = sess;
        std::thread([session]()
        {
            handlers::send_nmi_result(session);
        }).detach();
    }

}
