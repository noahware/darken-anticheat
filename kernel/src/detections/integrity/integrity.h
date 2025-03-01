#pragma once
#include "../../crypto/crypto_def.h"

namespace integrity
{
	crypto::s_hash calculate_image_section_hash(context::s_context* context, uint64_t image_base, const char* section_name);
}
