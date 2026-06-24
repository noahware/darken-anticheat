#pragma once
#include <stdint.h>
#include <stddef.h>

namespace cstd
{
	using ::int8_t;
	using ::int16_t;
	using ::int32_t;
	using ::int64_t;
	using ::uint8_t;
	using ::uint16_t;
	using ::uint32_t;
	using ::uint64_t;

	using ::size_t;

	using byte = unsigned char;

	static_assert(sizeof(size_t) == sizeof(void*));
}
