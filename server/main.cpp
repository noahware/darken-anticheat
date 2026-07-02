#include "client_conn.hpp"
#include "log.hpp"

#include <connection/session_manager.hpp>

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
                auto conn = std::static_pointer_cast<client_connection>(sess);

                conn->send_timestamp_request();
                conn->send_kernel_module_list_request();
                conn->send_thread_list_request();
                conn->send_nmi_check_request();
                conn->send_handle_strip_check_request();
                conn->send_reserved_msr_check_request();
                conn->send_protected_process_list_request();
                conn->send_kernel_data_page_exec_check_request();
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
        broadcast_check_requests(check_timer, manager, std::chrono::seconds(10));
        LOG_INFO("check request broadcast started (interval: 10s)");

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
