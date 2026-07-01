#pragma once
#include <cstdint>

static uint8_t* resolve_rip_relative(uint8_t* const code, const size_t rva_offset, const size_t rip_offset)
{
	const int32_t rva = *reinterpret_cast<const int32_t*>(code + rva_offset);

	return code + rva + rip_offset;
}
