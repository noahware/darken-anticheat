#pragma once
#include "generic_types.h"
#include "../context/context.h"

namespace crypto
{
	struct s_hash
	{
		uint8_t* buffer;
		uint32_t buffer_size;

		void free(context::s_context* context);
	};
}
