#include <connection/session_manager.hpp>
#include <network/socket.hpp>

#include <message/message.hpp>
#include <router/router.hpp>
#include <schema/request_generated.h>
#include <schema/response_generated.h>
#include <schema/client_timestamp_generated.h>
#include <schema/kernel_modules_generated.h>
#include <schema/event_generated.h>
#include <schema/thread_generated.h>
#include <schema/nmi_result_generated.h>
#include <schema/handle_strip_generated.h>
#include <schema/signature_generated.h>

#include "log.hpp"
#include "analysis.hpp"
#include "sign.hpp"

#include <mutex>

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

    void handle_client_timestamp_result(const std::shared_ptr<sl::session>& sess, const Anticheat::ClientTimestampResult* result)
    {
        LOG_INFO("client timestamp from {}:{}",
            sess->socket().remote_address(), sess->socket().port());
        analysis::process_client_timestamp(result);
    }

    class client_connection;

    void handle_kernel_module_list_result(const std::shared_ptr<client_connection>& conn, const Anticheat::KernelModuleList* result);
    void handle_event_batch_result(const std::shared_ptr<client_connection>& conn, const Anticheat::EventBatch* result);
    void handle_thread_list_result(const std::shared_ptr<client_connection>& conn, const Anticheat::ThreadList* result);
    void handle_nmi_result_data(const std::shared_ptr<client_connection>& conn, const Anticheat::NmiResult* result);
    void handle_image_signature_check_result(const std::shared_ptr<client_connection>& conn, const Anticheat::ImageSignatureCheckResult* result);
    void handle_handle_strip_result_data(const std::shared_ptr<client_connection>& conn, const Anticheat::HandleStripResult* result);

    constexpr sl::message_info<Anticheat::PingRequest, sl::session> ping_request{
        Anticheat::RequestId_Ping, handle_ping
    };

    constexpr sl::message_info<Anticheat::ClientTimestampResult, sl::session> client_timestamp_result{
        Anticheat::RequestId_ClientTimestampResult, handle_client_timestamp_result
    };

    constexpr sl::message_info<Anticheat::KernelModuleList, client_connection> kernel_module_list_result{
        Anticheat::RequestId_KernelModuleListResult, handle_kernel_module_list_result
    };

    constexpr sl::message_info<Anticheat::EventBatch, client_connection> event_batch_result{
        Anticheat::RequestId_EventBatchResult, handle_event_batch_result
    };

    constexpr sl::message_info<Anticheat::ThreadList, client_connection> thread_list_result{
        Anticheat::RequestId_ThreadListResult, handle_thread_list_result
    };

    constexpr sl::message_info<Anticheat::NmiResult, client_connection> nmi_result_data{
        Anticheat::RequestId_NmiResultData, handle_nmi_result_data
    };

    constexpr sl::message_info<Anticheat::ImageSignatureCheckResult, client_connection> image_signature_check_result{
        Anticheat::RequestId_ImageSignatureCheckResult, handle_image_signature_check_result
    };

    constexpr sl::message_info<Anticheat::HandleStripResult, client_connection> handle_strip_result_data{
        Anticheat::RequestId_HandleStripData, handle_handle_strip_result_data
    };

    using request_router = sl::message_router<ping_request, client_timestamp_result, kernel_module_list_result, event_batch_result, thread_list_result, nmi_result_data, image_signature_check_result, handle_strip_result_data>;

    class client_connection final : public sl::session
    {
    public:
        using session::session;

        std::vector<analysis::module_entry> kernel_modules_;
        std::vector<analysis::thread_entry> threads_;
        std::mutex modules_mutex_;

    protected:
        void handle_message(const message_id_t id, const body_buffer_t body) override
        {
            if (!request_router::dispatch(id, shared_as<client_connection>(), *body))
            {
                LOG_ERR("unknown request type: {}", id);
            }
        }
    };

    void send_signature_checks(const std::shared_ptr<client_connection>& conn,
                               const std::vector<std::string>& paths)
    {
        for (const auto& path : paths)
        {
            flatbuffers::FlatBufferBuilder fbb;
            auto path_offset = fbb.CreateString(path);
            auto req = Anticheat::CreateImageSignatureCheckRequest(fbb, path_offset);
            fbb.Finish(req);

            auto data = std::make_shared<std::vector<std::uint8_t>>(
                fbb.GetBufferPointer(), fbb.GetBufferPointer() + fbb.GetSize()
            );

            sl::msg::async_send_view(
                conn->socket(), Anticheat::ResponseId_ImageSignatureCheck,
                [data](bool) {},
                std::span<const std::uint8_t>{data->data(), data->size()}
            );
        }

        if (!paths.empty())
        {
            LOG_INFO("sent {} signature check request(s)", paths.size());
        }
    }

    void handle_kernel_module_list_result(const std::shared_ptr<client_connection>& conn, const Anticheat::KernelModuleList* result)
    {
        LOG_INFO("kernel module list from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        std::lock_guard<std::mutex> lock(conn->modules_mutex_);
        analysis::process_kernel_module_list(conn->kernel_modules_, result);

        const auto unsigned_paths = analysis::find_unsigned_modules(conn->kernel_modules_);
        send_signature_checks(conn, unsigned_paths);
    }

    void handle_event_batch_result(const std::shared_ptr<client_connection>& conn, const Anticheat::EventBatch* result)
    {
        LOG_INFO("event batch from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        std::lock_guard<std::mutex> lock(conn->modules_mutex_);
        analysis::process_event_batch(conn->kernel_modules_, result);

        const auto unsigned_paths = analysis::find_unsigned_modules(conn->kernel_modules_);
        send_signature_checks(conn, unsigned_paths);
    }

    void handle_thread_list_result(const std::shared_ptr<client_connection>& conn, const Anticheat::ThreadList* result)
    {
        LOG_INFO("thread list from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        std::lock_guard<std::mutex> lock(conn->modules_mutex_);
        analysis::process_thread_list(conn->threads_, conn->kernel_modules_, result);
    }

    void handle_nmi_result_data(const std::shared_ptr<client_connection>& conn, const Anticheat::NmiResult* result)
    {
        LOG_INFO("nmi result from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        std::lock_guard<std::mutex> lock(conn->modules_mutex_);
        analysis::process_nmi_result(conn->kernel_modules_, result);
    }

    void handle_image_signature_check_result(const std::shared_ptr<client_connection>& conn, const Anticheat::ImageSignatureCheckResult* result)
    {
        if (!result || !result->full_path())
        {
            LOG_ERR("null ImageSignatureCheckResult");
            return;
        }

        const auto path = result->full_path()->str();
        auto valid = false;

        if (result->data_type() == Anticheat::SignatureData_EmbeddedSignature)
        {
            const auto* emb = result->data_as_EmbeddedSignature();
            if (emb && emb->pkcs7())
            {
                valid = sign::verify_embedded({emb->pkcs7()->data(), emb->pkcs7()->size()});
            }
        }
        else if (result->data_type() == Anticheat::SignatureData_CatalogSignature)
        {
            const auto* cat = result->data_as_CatalogSignature();
            if (cat && cat->catalog_pkcs7() && cat->authenticode_hash())
            {
                valid = sign::verify_catalog(
                    {cat->catalog_pkcs7()->data(), cat->catalog_pkcs7()->size()},
                    {cat->authenticode_hash()->data(), cat->authenticode_hash()->size()}
                );
            }
        }

        if (valid)
        {
            std::lock_guard lock(conn->modules_mutex_);

            for (const auto& mod : conn->kernel_modules_)
            {
                if (mod.full_path == path)
                {
                    std::lock_guard hash_lock(analysis::verified_hashes_mutex);
                    analysis::verified_hashes.insert(analysis::to_hex(mod.hash));
                    LOG_INFO("module verified: {}", path);
                    break;
                }
            }
        }
        else
        {
            LOG_WARN("unsigned or untrusted module: {}", path);
        }
    }

    void handle_handle_strip_result_data(const std::shared_ptr<client_connection>& conn, const Anticheat::HandleStripResult* result)
    {
        LOG_INFO("handle strip result from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        analysis::process_handle_strip_result(result);
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
