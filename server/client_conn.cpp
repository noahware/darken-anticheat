#include "client_conn.hpp"

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
#include <schema/protected_process_generated.h>
#include <schema/kernel_data_page_exec_result_generated.h>

#include "log.hpp"
#include "sign.hpp"

#include <chrono>

namespace
{
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

    void handle_kernel_module_list_result(const std::shared_ptr<client_connection>& conn, const Anticheat::KernelModuleList* result);
    void handle_event_batch_result(const std::shared_ptr<client_connection>& conn, const Anticheat::EventBatch* result);
    void handle_thread_list_result(const std::shared_ptr<client_connection>& conn, const Anticheat::ThreadList* result);
    void handle_nmi_result_data(const std::shared_ptr<client_connection>& conn, const Anticheat::NmiResult* result);
    void handle_image_signature_check_result(const std::shared_ptr<client_connection>& conn, const Anticheat::ImageSignatureCheckResult* result);
    void handle_handle_strip_result_data(const std::shared_ptr<client_connection>& conn, const Anticheat::HandleStripResult* result);
    void handle_reserved_msr_result_data(const std::shared_ptr<client_connection>& conn, const Anticheat::ReservedMsrResult* result);
    void handle_protected_process_list_result(const std::shared_ptr<client_connection>& conn, const Anticheat::ProtectedProcessList* result);
    void handle_kernel_data_page_exec_check_result(const std::shared_ptr<client_connection>& conn, const Anticheat::KernelDataPageExecCheckResult* result);

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

    constexpr sl::message_info<Anticheat::ReservedMsrResult, client_connection> reserved_msr_result_data{
        Anticheat::RequestId_ReservedMsrData, handle_reserved_msr_result_data
    };

    constexpr sl::message_info<Anticheat::ProtectedProcessList, client_connection> protected_process_list_result{
        Anticheat::RequestId_ProtectedProcessListResult, handle_protected_process_list_result
    };

    constexpr sl::message_info<Anticheat::KernelDataPageExecCheckResult, client_connection> kernel_data_page_exec_check_result{
        Anticheat::RequestId_KernelDataPageExecResult, handle_kernel_data_page_exec_check_result
    };

    using request_router = sl::message_router<ping_request, client_timestamp_result, kernel_module_list_result, event_batch_result, thread_list_result, nmi_result_data, image_signature_check_result, handle_strip_result_data, reserved_msr_result_data, protected_process_list_result, kernel_data_page_exec_check_result>;

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
        analysis::process_kernel_module_list(*conn, conn->kernel_modules_, result);

        const auto unsigned_paths = analysis::find_unsigned_modules(conn->kernel_modules_);
        send_signature_checks(conn, unsigned_paths);
    }

    void handle_event_batch_result(const std::shared_ptr<client_connection>& conn, const Anticheat::EventBatch* result)
    {
        LOG_INFO("event batch from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        std::lock_guard<std::mutex> lock(conn->modules_mutex_);
        analysis::process_event_batch(*conn, conn->kernel_modules_, conn->processes_, result);

        auto unsigned_paths = analysis::find_unsigned_modules(conn->kernel_modules_);

        for (const auto& proc : conn->processes_)
        {
            auto paths = analysis::find_unsigned_modules(proc.modules);
            unsigned_paths.insert(unsigned_paths.end(), paths.begin(), paths.end());
        }

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
        analysis::process_nmi_result(conn->kernel_modules_, conn->processes_, result);
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
            if (emb && emb->pkcs7() && emb->authenticode_hash())
            {
                valid = sign::verify_embedded(
                    {emb->pkcs7()->data(), emb->pkcs7()->size()},
                    {emb->authenticode_hash()->data(), emb->authenticode_hash()->size()}
                );
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
            std::lock_guard hash_lock(analysis::verified_hashes_mutex);

            for (const auto& mod : conn->kernel_modules_)
            {
                if (mod.full_path == path)
                {
                    analysis::verified_hashes.insert(analysis::to_hex(mod.hash));
                    LOG_INFO("module verified: {}", path);
                    break;
                }
            }

            for (const auto& proc : conn->processes_)
            {
                for (const auto& mod : proc.modules)
                {
                    if (mod.full_path == path)
                    {
                        analysis::verified_hashes.insert(analysis::to_hex(mod.hash));
                        LOG_INFO("process module verified: {} (pid 0x{:x})", path, proc.process_id);
                    }
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

    void handle_reserved_msr_result_data(const std::shared_ptr<client_connection>& conn, const Anticheat::ReservedMsrResult* result)
    {
        LOG_INFO("reserved msr result from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        analysis::process_reserved_msr_result(result);
    }

    void handle_protected_process_list_result(const std::shared_ptr<client_connection>& conn, const Anticheat::ProtectedProcessList* result)
    {
        LOG_INFO("protected process list from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        std::lock_guard<std::mutex> lock(conn->modules_mutex_);
        analysis::process_protected_process_list(conn->processes_, result);

        std::vector<std::string> unsigned_paths;

        for (const auto& proc : conn->processes_)
        {
            auto paths = analysis::find_unsigned_modules(proc.modules);
            unsigned_paths.insert(unsigned_paths.end(), paths.begin(), paths.end());
        }

        send_signature_checks(conn, unsigned_paths);
    }

    void handle_kernel_data_page_exec_check_result(const std::shared_ptr<client_connection>& conn, const Anticheat::KernelDataPageExecCheckResult* result)
    {
        LOG_INFO("kernel data page exec result from {}:{}",
            conn->socket().remote_address(), conn->socket().port());

        std::lock_guard lock(conn->modules_mutex_);

        analysis::process_kernel_data_page_exec_check_result(conn->kernel_modules_, result);
    }
}

void client_connection::send_timestamp_request()
{
    send_round_request<Anticheat::CreateClientTimestampRequest, Anticheat::ResponseId_ClientTimestamp, Anticheat::RequestId_ClientTimestampResult>();
}

void client_connection::send_kernel_module_list_request()
{
    send_round_request<Anticheat::CreateKernelModuleListRequest, Anticheat::ResponseId_KernelModuleList, Anticheat::RequestId_KernelModuleListResult>();
}

void client_connection::send_thread_list_request()
{
    send_round_request<Anticheat::CreateThreadListRequest, Anticheat::ResponseId_ThreadList, Anticheat::RequestId_ThreadListResult>();
}

void client_connection::send_nmi_check_request()
{
    send_round_request<Anticheat::CreateNmiCheckRequest, Anticheat::ResponseId_NmiCheck, Anticheat::RequestId_NmiResultData>();
}

void client_connection::send_handle_strip_check_request()
{
    send_round_request<Anticheat::CreateHandleStripCheckRequest, Anticheat::ResponseId_HandleStripCheck, Anticheat::RequestId_HandleStripData>();
}

void client_connection::send_reserved_msr_check_request()
{
    send_round_request<Anticheat::CreateReservedMsrCheckRequest, Anticheat::ResponseId_ReservedMsrCheck, Anticheat::RequestId_ReservedMsrData>();
}

void client_connection::send_protected_process_list_request()
{
    send_round_request<Anticheat::CreateProtectedProcessListRequest, Anticheat::ResponseId_ProtectedProcessList, Anticheat::RequestId_ProtectedProcessListResult>();
}

void client_connection::send_kernel_data_page_exec_check_request()
{
    send_round_request<Anticheat::CreateKernelDataPageExecCheckRequest, Anticheat::ResponseId_KernelDataPageExecCheck, Anticheat::RequestId_KernelDataPageExecResult>();
}

void client_connection::popup_close_client(const std::string& msg)
{
    flatbuffers::FlatBufferBuilder fbb;
    auto msg_offset = fbb.CreateString(msg);
    auto req = Anticheat::CreatePopupCloseClientRequest(fbb, msg_offset);
    fbb.Finish(req);

    auto data = std::make_shared<std::vector<std::uint8_t>>(
        fbb.GetBufferPointer(), fbb.GetBufferPointer() + fbb.GetSize()
    );

    sl::msg::async_send_view(
        socket(), Anticheat::ResponseId_PopupCloseClient,
        [self = shared_from_this(), data](bool) { self->stop(); },
        std::span<const std::uint8_t>{data->data(), data->size()}
    );
}

void client_connection::handle_message(const message_id_t id, const body_buffer_t body)
{
    if (!request_router::dispatch(id, shared_as<client_connection>(), *body))
    {
        LOG_ERR("unknown request type: {}", id);
        return;
    }

    std::lock_guard lock(pending_responses_mutex_);
    pending_responses_.erase(static_cast<std::uint8_t>(id));
}
