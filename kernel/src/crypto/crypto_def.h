#pragma once
#include "generic_types.h"
#include "../context/context.h"

namespace crypto
{
	struct s_hash
	{
		uint8_t* buffer;
		uint32_t buffer_size;

		bool is_same(s_hash& other);
		void free(context::s_context* context);
	};
}
