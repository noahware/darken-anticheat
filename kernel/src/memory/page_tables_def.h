#pragma once
#include <ia32/ia32.h>

// should not pass 255, otherwise will be overwriting potential kernel entries
#define d_pml4e_to_map_into 1ull

namespace page_tables
{
	// we are going to use 'huge pages' (pdpt describing 1gb each), which should be fine for any cpu made after late 2000s
	// if this will cause a collision with some systems, then we will map pds in too for each pdpte in our held pml4e
	struct s_page_table
	{
		pml4e_64 pml4[512];
		pdpte_1gb_64 pdpt[512]; // pdpt that will be mapped into the pml4e we control
	};

	inline constexpr uint64_t pt_access_virtual_address = d_pml4e_to_map_into << 39;
}
