#pragma once
#include <connection/session.hpp>
#include <message/message.hpp>

#include "analysis.hpp"
#include "log.hpp"

#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

class client_connection final : public sl::session
{
public:
    using session::session;

    std::vector<analysis::module_entry> kernel_modules_;
    std::vector<analysis::process_entry> processes_;
    std::vector<analysis::thread_entry> threads_;
    std::mutex modules_mutex_;
    std::mutex pending_responses_mutex_;
    std::unordered_set<std::uint8_t> pending_responses_;

    template <auto CreateFn, std::uint8_t send_id, std::uint8_t expect_id>
    void send_round_request()
    {
        {
            std::lock_guard lock(pending_responses_mutex_);
            if (pending_responses_.contains(expect_id))
            {
                LOG_WARN("client {}:{} did not respond to check {}",
                    socket().remote_address(), socket().port(), expect_id);
            }
            pending_responses_.insert(expect_id);
        }
        sl::msg::async_send<CreateFn>(socket(), send_id);
    }

    void send_timestamp_request();
    void send_kernel_module_list_request();
    void send_thread_list_request();
    void send_nmi_check_request();
    void send_handle_strip_check_request();
    void send_reserved_msr_check_request();
    void send_protected_process_list_request();
    void send_kernel_data_page_exec_check_request();

    void popup_close_client(const std::string& msg);

protected:
    void handle_message(message_id_t id, body_buffer_t body) override;
};
