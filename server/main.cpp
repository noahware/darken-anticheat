#include <connection/session_manager.hpp>
#include <network/socket.hpp>

#include <message/message.hpp>
#include <router/router.hpp>
#include <schema/request_generated.h>
#include <schema/response_generated.h>

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

    constexpr sl::message_info<Anticheat::PingRequest, sl::session> ping_request{
        Anticheat::RequestId_Ping, handle_ping
    };

    using request_router = sl::message_router<ping_request>;

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

        boost::asio::signal_set signals(pool.get_executor(), SIGINT, SIGTERM);
        signals.async_wait([manager](const boost::system::error_code&, int)
        {
            LOG_INFO("shutting down");
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
