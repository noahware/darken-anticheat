#pragma once
#include <connection/session.hpp>

#include "analysis.hpp"

#include <mutex>
#include <string>
#include <vector>

class client_connection final : public sl::session
{
public:
    using session::session;

    std::vector<analysis::module_entry> kernel_modules_;
    std::vector<analysis::process_entry> processes_;
    std::vector<analysis::thread_entry> threads_;
    std::mutex modules_mutex_;

    void popup_close_client(const std::string& msg);

protected:
    void handle_message(message_id_t id, body_buffer_t body) override;
};
