#include "page_tables.h"
#include "../os/ntkrnl/ntkrnl.h"
#include <ntifs.h>

bool page_tables::load(context::s_context* context)
{
	page_tables = reinterpret_cast<s_page_table*>(context->imports.ex_allocate_pool_2(POOL_FLAG_NON_PAGED, sizeof(s_page_table), d_pool_tag));

	if (page_tables == nullptr)
	{
		return false;
	}

	memset(page_tables, 0, sizeof(s_page_table));

	pml4e_64* target_pml4e = &page_tables->pml4[d_pml4e_to_map_into];

	target_pml4e->present = 1;
	target_pml4e->write = 1;
	target_pml4e->page_frame_number = context->imports.mm_get_physical_address(reinterpret_cast<uint64_t>(&page_tables->pdpt)) >> 12;

	for (uint32_t i = 0; i < 512; i++)
	{
		pdpte_1gb_64* current_pdpte = &page_tables->pdpt[i];

		current_pdpte->present = 1;
		current_pdpte->write = 1;
		current_pdpte->large_page = 1;
		current_pdpte->page_frame_number = i;
	}

	// need to copy over kernel entries now otherwise our code wont be even able to execute when we load these page tables into cr3 reg
	// 
	// im going to get virtual address of the system pml4 through MmGetVirtualForPhysical
	// as opposed to reading from the physical address using MmCopyMemory due to MmCopyMemory being slower

	uint64_t system_directory_table_base_physical = ntkrnl::get_process_directory_table_base(context->initial_system_process);

	if (system_directory_table_base_physical == 0) // never should happen
	{
		return false;
	}

	pml4e_64* system_directory_table_base_virtual = reinterpret_cast<pml4e_64*>(context->imports.mm_get_virtual_for_physical(system_directory_table_base_physical));

	if (system_directory_table_base_virtual == nullptr)
	{
		return false;
	}

	memcpy(&page_tables->pml4[256], &system_directory_table_base_virtual[256], sizeof(pml4e_64) * 256);

	pt_cr3.address_of_page_directory = context->imports.mm_get_physical_address(reinterpret_cast<uint64_t>(&page_tables->pml4)) >> 12;

	return true;
}

void page_tables::unload(context::s_context* context)
{
	if (page_tables != nullptr)
	{
		context->imports.ex_free_pool_with_tag(reinterpret_cast<uint64_t>(page_tables), d_pool_tag);
	}
}
