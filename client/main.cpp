#include <network/socket.hpp>
#include <message/message.hpp>
#include <schema/request_generated.h>
#include <schema/response_generated.h>

#include "log.hpp"

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
}

std::int32_t main()
{
    try
    {
        LOG_INFO("anticheat client");

        boost::asio::io_context io_context;
        const auto ssl_ctx = std::make_shared<sl::boost_ssl_context>(
            sl::boost_ssl_context::ssl_method_type::tlsv12_client
        );
        set_up_ssl_context(*ssl_ctx);

        sl::boost_tcp_socket sock(io_context.get_executor(), ssl_ctx);

        if (!sock.connect("127.0.0.1", "27015"))
        {
            LOG_ERR("failed to connect to server");
            return 1;
        }

        if (!sock.handshake(sl::socket::handshake_type::client))
        {
            LOG_ERR("handshake failed");
            return 1;
        }

        LOG_INFO("connected to server");

        const auto timestamp = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );

        sl::msg::send<Anticheat::CreatePingRequest>(sock, Anticheat::RequestId_Ping, timestamp);
        LOG_INFO("sent ping (timestamp: {})", timestamp);

        std::vector<std::uint8_t> response_buffer;
        const auto* response = sl::msg::recv<Anticheat::PongResponse>(sock, response_buffer);

        if (!response)
        {
            LOG_ERR("failed to receive pong");
            return 1;
        }

        const auto now = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()
            ).count()
        );

        LOG_INFO("pong from server (rtt: {}ms, server_time: {})",
            now - response->client_timestamp(),
            response->server_timestamp()
        );
    }
    catch (const std::exception& e)
    {
        LOG_ERR(e.what());
    }

    return 0;
}
