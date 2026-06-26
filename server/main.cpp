#include <connection/session_manager.hpp>
#include <network/socket.hpp>

#include <message/message.hpp>
#include <router/router.hpp>
#include <schema/request_generated.h>
#include <schema/response_generated.h>
#include <schema/example_check_generated.h>
#include <schema/client_timestamp_generated.h>

#include "log.hpp"
#include "analysis.hpp"

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

    void handle_ping(const std::shared_ptr<sl::session>& sess, const Anticheat::PingRequest* request)
    {
        LOG_INFO("ping from client (timestamp: {})", request->timestamp());

        const auto now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );

        sl::msg::async_send<Anticheat::CreatePongResponse>(
            sess->socket(), Anticheat::ResponseId_Pong,
            request->timestamp(), now
        );
    }

    void handle_example_check_result(const std::shared_ptr<sl::session>& sess, const Anticheat::ExampleCheckResult* result)
    {
        LOG_INFO("example check result from {}:{}",
            sess->socket().remote_address(), sess->socket().port());
        analysis::process_example_check(result);
    }

    void handle_client_timestamp_result(const std::shared_ptr<sl::session>& sess, const Anticheat::ClientTimestampResult* result)
    {
        LOG_INFO("client timestamp from {}:{}",
            sess->socket().remote_address(), sess->socket().port());
        analysis::process_client_timestamp(result);
    }

    constexpr sl::message_info<Anticheat::PingRequest, sl::session> ping_request{
        Anticheat::RequestId_Ping, handle_ping
    };

    constexpr sl::message_info<Anticheat::ExampleCheckResult, sl::session> example_check_result{
        Anticheat::RequestId_ExampleCheckResult, handle_example_check_result
    };

    constexpr sl::message_info<Anticheat::ClientTimestampResult, sl::session> client_timestamp_result{
        Anticheat::RequestId_ClientTimestampResult, handle_client_timestamp_result
    };

    using request_router = sl::message_router<ping_request, example_check_result, client_timestamp_result>;

    class client_connection final : public sl::session
    {
    public:
        using session::session;

    protected:
        void handle_message(const message_id_t id, const body_buffer_t body) override
        {
            if (!request_router::dispatch(id, shared_as<sl::session>(), *body))
            {
                LOG_ERR("unknown request type: {}", id);
            }
        }
    };

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
                sl::msg::async_send<Anticheat::CreateExampleCheckRequest>(
                    sess->socket(), Anticheat::ResponseId_ExampleCheck
                );

                sl::msg::async_send<Anticheat::CreateClientTimestampRequest>(
                    sess->socket(), Anticheat::ResponseId_ClientTimestamp
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
        manager->set_heartbeat_timeout(std::chrono::seconds(5));
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
        broadcast_check_requests(check_timer, manager, std::chrono::seconds(30));
        LOG_INFO("check request broadcast started (interval: 30s)");

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
