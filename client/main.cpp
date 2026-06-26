#include <network/socket.hpp>
#include <message/message.hpp>
#include <schema/request_generated.h>

#include "log.hpp"
#include "driver.hpp"
#include "client_session.hpp"

#include <chrono>

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

        boost::asio::signal_set signals(io_context.get_executor(), SIGINT, SIGTERM);
        signals.async_wait([&](const boost::system::error_code&, int)
        {
            LOG_INFO("shutting down");
            session->stop();
            driver::close();
        });

        io_context.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERR(e.what());
    }

    return 0;
}
