#pragma once
#include <portable_executable/image.hpp>
#include "types.hpp"

namespace krnl
{
	inline portable_executable::image_t* nt = nullptr;
	inline _MMPFN* mm_pfn_database = nullptr;
}
