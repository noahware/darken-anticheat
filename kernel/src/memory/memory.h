#pragma once
#include "../structures/virtual_address.h"
#include <ia32/ia32.h>

namespace memory
{
	// note: cr3 must hold page_tables::pt_cr3 when invoking this function
	uint64_t translate_virtual_address(s_virtual_address virtual_address, cr3 directory_table_base);

	bool is_address_valid(uint64_t virtual_address, uint64_t directory_table_base);

	namespace current_context
	{
		void write_cr3(cr3 value);

		cr3 read_cr3();
	}
}
