#pragma once
#include <communication_types.h>
#include "../../crypto/crypto_def.h"

namespace integrity
{
	int32_t calculate_image_section_hash(context::s_context* context, uint64_t image_base, const char* section_name, crypto::s_hash* hash_out);

	communication::e_detection_status validate_ntoskrnl_integrity(context::s_context* context);
	communication::e_detection_status validate_kernel_drivers_integrity(context::s_context* context);
}
