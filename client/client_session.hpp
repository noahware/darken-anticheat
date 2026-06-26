#pragma once
#include <connection/session.hpp>

class client_session final : public sl::session
{
public:
    using session::session;

protected:
    void handle_message(message_id_t id, body_buffer_t body) override;
    void on_error() override;
};
