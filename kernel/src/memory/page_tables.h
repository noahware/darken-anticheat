#pragma once
#include "../context/context.h"
#include <ia32/ia32.h>

// should not pass 255, otherwise will be overwriting potential kernel entries
#define d_pml4e_to_map_into 1ull

namespace page_tables
{
	bool load(context::s_context* context);
	void unload(context::s_context* context);
}
