#include "memory.h"
#include "page_tables.h"
#include "../context/context.h"

#include <intrin.h>
#include "../os/hvl/enlightenments.h"

struct s_pte
{
	uint64_t physical_address;
	uint32_t size;

	uint8_t is_executable;
};

void process_translation_pte_info(uint64_t* size_left_of_page, bool* is_executable, uint64_t page_size, uint64_t page_offset, uint64_t execute_disable)
{
	if (size_left_of_page)
	{
		*size_left_of_page = page_size - page_offset;
	}

	if (is_executable)
	{
		*is_executable = (execute_disable == 0);
	}
}

uint64_t memory::translate_virtual_address(s_virtual_address virtual_address, cr3 directory_table_base, uint64_t* size_left_of_page, bool* is_executable)
{
	if (virtual_address.address == 0 || directory_table_base.flags == 0)
	{
		return 0;
	}

	pml4e_64* pml4 = reinterpret_cast<pml4e_64*>(page_tables::pt_access_virtual_address + (directory_table_base.address_of_page_directory << 12));

	pml4e_64 pml4e = pml4[virtual_address.pml4_idx];

	if (pml4e.present == 0)
	{
		return 0;
	}

	pdpte_64* pdpt = reinterpret_cast<pdpte_64*>(page_tables::pt_access_virtual_address + (pml4e.page_frame_number << 12));

	pdpte_64 pdpte = pdpt[virtual_address.pdpt_idx];

	if (pdpte.present == 0)
	{
		return 0;
	}

	if (pdpte.large_page == 1)
	{
		pdpte_1gb_64 pdpte_1gb = { .flags = pdpte.flags };

		uint64_t page_offset = virtual_address.offset + (virtual_address.pt_idx << 12) + (virtual_address.pd_idx << 21);

		process_translation_pte_info(size_left_of_page, is_executable, 0x40000000, page_offset, pml4e.execute_disable | pdpte_1gb.execute_disable);

		return page_offset + (pdpte_1gb.page_frame_number << 30);
	}

	pde_64* pd = reinterpret_cast<pde_64*>(page_tables::pt_access_virtual_address + (pdpte.page_frame_number << 12));

	pde_64 pde = pd[virtual_address.pd_idx];

	if (pde.present == 0)
	{
		return 0;
	}

	if (pde.large_page == 1)
	{
		pde_2mb_64 pde_2mb = { .flags = pde.flags };

		uint64_t page_offset = virtual_address.offset + (virtual_address.pt_idx << 12);

		process_translation_pte_info(size_left_of_page, is_executable, 0x200000, page_offset, pde_2mb.execute_disable | pml4e.execute_disable | pdpte.execute_disable);

		return page_offset + (pde_2mb.page_frame_number << 21);
	}

	pte_64* pt = reinterpret_cast<pte_64*>(page_tables::pt_access_virtual_address + (pde.page_frame_number << 12));

	pte_64 pte = pt[virtual_address.pt_idx];

	if (pte.present == 0)
	{
		return 0;
	}

	process_translation_pte_info(size_left_of_page, is_executable, 0x1000, virtual_address.offset, pte.execute_disable | pde.execute_disable | pml4e.execute_disable | pdpte.execute_disable);

	return virtual_address.offset + (pte.page_frame_number << 12);
}

bool memory::is_address_valid(uint64_t virtual_address, uint64_t directory_table_base)
{
	return translate_virtual_address({ virtual_address }, { .flags = directory_table_base }) != 0;
}

uint64_t memory::allocate_pool(context::s_context* context, uint64_t size, uint64_t flags, uint32_t tag)
{
	return context->imports.ex_allocate_pool_2(flags, size, tag);
}

void memory::free_pool(context::s_context* context, uint64_t pool_address, uint32_t tag)
{
	context->imports.ex_free_pool_with_tag(pool_address, tag);
}

void memory::current_context::write_cr3(cr3 value)
{
	if (hvl::get_enlightenments() & 1)
	{
		context::get_decrypted()->imports.hvl_switch_virtual_address_space(value.flags);
	}
	else
	{
		__writecr3(value.flags);
	}
}

cr3 memory::current_context::read_cr3()
{
	return { .flags = __readcr3() };
}
