#include <network/socket.hpp>
#include <message/message.hpp>
#include <schema/request_generated.h>

#include "log.hpp"
#include "driver.hpp"
#include "handlers.hpp"
#include "request_forwarder.hpp"
#include "client_session.hpp"
#include <chrono>
#include <cstring>
#include <thread>
#include <atomic>

namespace
{
    void set_up_ssl_context(sl::ssl_context& context)
    {
        context.require_peer_verification();

        context.load_verify_file("certificate_authority.pem");
        context.use_certificate("client_certificate.pem", sl::ssl_context::crypto_file_format::pem);
        context.use_private_key("client_private_key.pem", sl::ssl_context::crypto_file_format::pem);
        context.use_tmp_dh_file("dhparams.pem");
    }

    void send_ping(sl::socket& sock)
    {
        const auto timestamp = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );

        sl::msg::send<Anticheat::CreatePingRequest>(sock, Anticheat::RequestId_Ping, timestamp);
        LOG_INFO("sent ping (timestamp: {})", timestamp);
    }

    HANDLE shutdown_event = nullptr;

    void driver_thread(const std::shared_ptr<sl::session>& session)
    {
        if (!request::send_from_driver<Anticheat::ResponseId_KernelModuleList, Anticheat::RequestId_KernelModuleListResult>(session))
        {
            LOG_ERR("failed to send initial module list");
            return;
        }

        auto handle_opt = driver::get_event_handle();

        if (!handle_opt)
        {
            LOG_ERR("failed to get event handle from driver");
            return;
        }

        const auto event_handle = *handle_opt;
        LOG_INFO("event listener started");

        const HANDLE wait_handles[] = { event_handle, shutdown_event };

        while (true)
        {
            const auto wait_result = WaitForMultipleObjects(2, wait_handles, FALSE, INFINITE);

            if (wait_result == WAIT_OBJECT_0 + 1)
            {
                break;
            }

            if (wait_result == WAIT_OBJECT_0)
            {
                auto events = driver::drain_events();

                if (!events)
                {
                    LOG_ERR("failed to drain events");
                    break;
                }

                auto event_data = std::make_shared<std::vector<std::uint8_t>>(std::move(*events));

                sl::msg::async_send_view(
                    session->socket(), Anticheat::RequestId_EventBatchResult,
                    [event_data](bool) {},
                    std::span<const std::uint8_t>{event_data->data(), event_data->size()}
                );

                LOG_INFO("sent event batch (size: {})", event_data->size());
            }
            else
            {
                LOG_ERR("event wait failed (result: {})", wait_result);
                break;
            }
        }

        CloseHandle(event_handle);
        LOG_INFO("event listener stopped");
    }
}

std::int32_t main()
{
    try
    {
        LOG_INFO("anticheat client");

        if (!driver::open())
        {
            LOG_ERR("failed to open driver device, continuing without driver");
        }
        else if (!driver::protect_self())
        {
            LOG_ERR("failed to register as protected process");
        }

        boost::asio::io_context io_context;
        const auto ssl_ctx = std::make_shared<sl::boost_ssl_context>(
            sl::boost_ssl_context::ssl_method_type::tlsv12_client
        );
        set_up_ssl_context(*ssl_ctx);

        auto socket = std::make_unique<sl::boost_tcp_socket>(io_context.get_executor(), ssl_ctx);
        auto session = std::make_shared<client_session>(std::move(socket));

        if (!session->connect("127.0.0.1", "27015"))
        {
            LOG_ERR("failed to connect to server");
            return 1;
        }

        if (!session->handshake(sl::socket::handshake_type::client))
        {
            LOG_ERR("handshake failed");
            return 1;
        }

        LOG_INFO("connected to server");

        send_ping(session->socket());
        session->start();

        shutdown_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);

        std::thread event_thread;

        if (driver::is_open())
        {
            event_thread = std::thread(driver_thread, session);
        }

        boost::asio::signal_set signals(io_context.get_executor(), SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int)
        {
            LOG_INFO("shutting down");
            session->stop();
            driver::cancel_io();
            SetEvent(shutdown_event);
        });

        io_context.run();

        driver::cancel_io();
        SetEvent(shutdown_event);

        if (event_thread.joinable())
        {
            event_thread.join();
        }

        driver::close();
        CloseHandle(shutdown_event);
    }
    catch (const std::exception& e)
    {
        LOG_ERR(e.what());
    }

    return 0;
}
