#pragma once
#include <communication_types.h>
#include "../../crypto/crypto_def.h"

namespace integrity::data_section
{
	communication::e_detection_status is_any_driver_data_section_executable(context::s_context* context);
}
