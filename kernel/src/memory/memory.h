#pragma once
#include "../structures/virtual_address.h"
#include "../context/context.h"
#include <ia32/ia32.h>

namespace memory
{
	// note: cr3 must hold page_tables::pt_cr3 when invoking this function
	uint64_t translate_virtual_address(s_virtual_address virtual_address, cr3 directory_table_base);

	bool is_address_valid(uint64_t virtual_address, uint64_t directory_table_base);
	uint64_t allocate_pool(context::s_context* context, uint64_t size, uint64_t flags, uint32_t tag = d_pool_tag);
	void free_pool(context::s_context* context, uint64_t pool_address, uint32_t tag = d_pool_tag);

	namespace current_context
	{
		void write_cr3(cr3 value);

		cr3 read_cr3();
	}
}
