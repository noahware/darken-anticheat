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

	uint64_t xor64(uint64_t input, uint64_t key);

	int32_t sha256(context::s_context* context, uint8_t* buffer, uint32_t buffer_size, uint8_t** hash_buffer, uint32_t* hash_size);
	s_hash sha256(context::s_context* context, uint8_t* buffer, uint32_t buffer_size);
}
