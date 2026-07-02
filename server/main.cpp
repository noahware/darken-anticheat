#include "client_conn.hpp"

#include <connection/session_manager.hpp>
#include <message/message.hpp>
#include <schema/response_generated.h>
#include <schema/client_timestamp_generated.h>
#include <schema/kernel_modules_generated.h>
#include <schema/thread_generated.h>
#include <schema/nmi_result_generated.h>
#include <schema/handle_strip_generated.h>
#include <schema/protected_process_generated.h>
#include <schema/kernel_data_page_exec_result_generated.h>

#include "log.hpp"

namespace
{
    void set_up_ssl_context(sl::ssl_context& context)
    {
        context.require_peer_verification();

        context.load_verify_file("certificate_authority.pem");
        context.use_certificate("server_certificate.pem", sl::ssl_context::crypto_file_format::pem);
        context.use_private_key("server_private_key.pem", sl::ssl_context::crypto_file_format::pem);
        context.use_tmp_dh_file("dhparams.pem");
    }

    void broadcast_check_requests(
        boost::asio::steady_timer& timer,
        const std::shared_ptr<sl::boost_session_manager<client_connection>>& manager,
        const std::chrono::seconds interval)
    {
        timer.expires_after(interval);
        timer.async_wait([&timer, manager, interval](const boost::system::error_code& ec)
        {
            if (ec)
            {
                return;
            }

            manager->for_each_session([](const std::shared_ptr<sl::session>& sess)
            {
                sl::msg::async_send<Anticheat::CreateClientTimestampRequest>(
                    sess->socket(), Anticheat::ResponseId_ClientTimestamp
                );

                sl::msg::async_send<Anticheat::CreateKernelModuleListRequest>(
                    sess->socket(), Anticheat::ResponseId_KernelModuleList
                );

                sl::msg::async_send<Anticheat::CreateThreadListRequest>(
                    sess->socket(), Anticheat::ResponseId_ThreadList
                );

                sl::msg::async_send<Anticheat::CreateNmiCheckRequest>(
                    sess->socket(), Anticheat::ResponseId_NmiCheck
                );

                sl::msg::async_send<Anticheat::CreateHandleStripCheckRequest>(
                    sess->socket(), Anticheat::ResponseId_HandleStripCheck
                );

                sl::msg::async_send<Anticheat::CreateReservedMsrCheckRequest>(
                    sess->socket(), Anticheat::ResponseId_ReservedMsrCheck
                );

                sl::msg::async_send<Anticheat::CreateProtectedProcessListRequest>(
                    sess->socket(), Anticheat::ResponseId_ProtectedProcessList
                );

                sl::msg::async_send<Anticheat::CreateKernelDataPageExecCheckRequest>(
                    sess->socket(), Anticheat::ResponseId_KernelDataPageExecCheck
                );
            });

            LOG_INFO("sent check requests to {} client(s)", manager->session_count());

            broadcast_check_requests(timer, manager, interval);
        });
    }
}

std::int32_t main()
{
    try
    {
        const auto thread_count = std::thread::hardware_concurrency();
        LOG_INFO("anticheat server (threads: {})", thread_count);

        const auto ssl_ctx = std::make_shared<sl::boost_ssl_context>(
            sl::boost_ssl_context::ssl_method_type::tlsv12_server
        );
        set_up_ssl_context(*ssl_ctx);

        boost::asio::thread_pool pool(thread_count);

        const auto manager = std::make_shared<sl::boost_session_manager<client_connection>>(
            pool.get_executor(), ssl_ctx, 27015
        );

        manager->set_idle_timeout(std::chrono::seconds(30));
        manager->set_heartbeat_timeout(std::chrono::seconds(30));
        manager->set_handshake_timeout(std::chrono::seconds(5));
        manager->set_max_message_size(1024 * 1024);

        manager->on_connect([](const std::shared_ptr<sl::session>& sess)
        {
            LOG_INFO("client connected: {}:{}", sess->socket().remote_address(), sess->socket().port());
        });

        manager->on_disconnect([](const std::shared_ptr<sl::session>& sess)
        {
            LOG_INFO("client disconnected: {}:{}", sess->socket().remote_address(), sess->socket().port());
        });

        manager->async_wait_for_connection();

        boost::asio::steady_timer check_timer(pool.get_executor());
        broadcast_check_requests(check_timer, manager, std::chrono::seconds(5));
        LOG_INFO("check request broadcast started (interval: 5s)");

        boost::asio::signal_set signals(pool.get_executor(), SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int)
        {
            LOG_INFO("shutting down");
            check_timer.cancel();
            manager->stop();
        });

        LOG_INFO("listening on port 27015");
        pool.join();
    }
    catch (const std::exception& e)
    {
        LOG_ERR(e.what());
    }

    return 0;
}
