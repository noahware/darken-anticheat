#pragma once
#include <connection/session.hpp>
#include <schema/response_generated.h>
#include <schema/signature_generated.h>

namespace handlers
{
    void handle_pong(const std::shared_ptr<sl::session>& sess, const Anticheat::PongResponse* pong);
    void handle_client_timestamp(const std::shared_ptr<sl::session>& sess, const Anticheat::ClientTimestampRequest* request);
    void handle_image_signature_check(const std::shared_ptr<sl::session>& sess, const Anticheat::ImageSignatureCheckRequest* request);
    void handle_popup_close(const std::shared_ptr<sl::session>& sess, const Anticheat::PopupCloseClientRequest* request);
}
