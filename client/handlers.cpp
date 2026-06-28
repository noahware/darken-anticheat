#include "handlers.hpp"
#include "driver.hpp"
#include "sign.hpp"
#include "log.hpp"

#include <message/message.hpp>
#include <schema/request_generated.h>
#include <schema/client_timestamp_generated.h>
#include <schema/response_generated.h>
#include <schema/kernel_modules_generated.h>
#include <schema/thread_generated.h>
#include <schema/nmi_result_generated.h>
#include <schema/signature_generated.h>

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

    void handle_image_signature_check(
        const std::shared_ptr<sl::session>& sess,
        const Anticheat::ImageSignatureCheckRequest* request)
    {
        if (!request || !request->full_path())
        {
            LOG_ERR("null ImageSignatureCheckRequest");
            return;
        }

        const auto path = request->full_path()->str();
        LOG_INFO("received signature check request: {}", path);

        auto session = sess;
        std::thread([session, path]()
        {
            const auto result = sign::extract(path);

            flatbuffers::FlatBufferBuilder fbb(4096);

            auto path_offset = fbb.CreateString(path);

            flatbuffers::Offset<Anticheat::ImageSignatureCheckResult> result_offset;

            if (std::holds_alternative<sign::embedded_data>(result))
            {
                const auto& emb = std::get<sign::embedded_data>(result);
                auto pkcs7_offset = fbb.CreateVector(emb.pkcs7.data(), emb.pkcs7.size());
                auto emb_offset = Anticheat::CreateEmbeddedSignature(fbb, pkcs7_offset);
                result_offset = Anticheat::CreateImageSignatureCheckResult(
                    fbb, path_offset,
                    Anticheat::SignatureData_EmbeddedSignature,
                    emb_offset.Union()
                );
            }
            else if (std::holds_alternative<sign::catalog_data>(result))
            {
                const auto& cat = std::get<sign::catalog_data>(result);
                auto hash_offset = fbb.CreateVector(cat.authenticode_hash.data(), cat.authenticode_hash.size());
                auto pkcs7_offset = fbb.CreateVector(cat.catalog_pkcs7.data(), cat.catalog_pkcs7.size());
                auto cat_offset = Anticheat::CreateCatalogSignature(fbb, hash_offset, pkcs7_offset);
                result_offset = Anticheat::CreateImageSignatureCheckResult(
                    fbb, path_offset,
                    Anticheat::SignatureData_CatalogSignature,
                    cat_offset.Union()
                );
            }
            else
            {
                result_offset = Anticheat::CreateImageSignatureCheckResult(
                    fbb, path_offset
                );
            }

            fbb.Finish(result_offset);

            auto data = std::make_shared<std::vector<std::uint8_t>>(
                fbb.GetBufferPointer(), fbb.GetBufferPointer() + fbb.GetSize()
            );

            sl::msg::async_send_view(
                session->socket(), Anticheat::RequestId_ImageSignatureCheckResult,
                [data](bool) {},
                std::span<const std::uint8_t>{data->data(), data->size()}
            );

            LOG_INFO("sent signature check result for {} ({} bytes)", path, data->size());
        }).detach();
    }

}
