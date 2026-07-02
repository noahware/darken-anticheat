#include "mem.hpp"

#include <intrin.h>

#include "../krnl/nt_status.hpp"

template <typename... Entries>
page_flags compute_flags(const Entries&... entries)
{
	auto result = static_cast<uint8_t>(page_read);

	if ((entries.write && ...))
	{
		result |= page_write;
	}

	if ((!entries.execute_disable && ...))
	{
		result |= page_execute;
	}

	if ((!entries.supervisor || ...))
	{
		result |= page_supervisor;
	}

	return static_cast<page_flags>(result);
}

cr3 mem::curr_cr3()
{
	return cr3{ .flags = __readcr3() };
}

cstd::optional<mem::phys_addr_t> mem::translate_virt_addr(const cr3 cr3, const virt_addr_t addr,
                                                          page_flags* const flags)
{
	if (flags)
	{
		*flags = page_none;
	}

	bool success = false;

	const auto pml4e = read_physical_memory<pml4e_64>(
		(cr3.address_of_page_directory << page_shift) + addr.pml4e * sizeof(pml4e_64), &success);

	if (!success || !pml4e.present)
	{
		return { };
	}

	const auto pdpte = read_physical_memory<pdpte_64>(
		(pml4e.page_frame_number << page_shift) + addr.pdpte * sizeof(pdpte_64), &success);

	if (!success || !pdpte.present)
	{
		return { };
	}

	if (pdpte.large_page)
	{
		const pdpte_1gb_64 large_pdpte = { .flags = pdpte.flags };
		const size_t page_offset = (addr.pde << pde_shift) + (addr.pte << pte_shift) + addr.page_off;

		if (flags)
		{
			*flags = compute_flags(pml4e, large_pdpte);
		}

		return (large_pdpte.page_frame_number << pdpte_shift) + page_offset;
	}

	const auto pde = read_physical_memory<pde_64>(
		(pdpte.page_frame_number << page_shift) + addr.pde * sizeof(pde_64), &success);

	if (!success || !pde.present)
	{
		return { };
	}

	if (pde.large_page)
	{
		const pde_2mb_64 large_pde = { .flags = pde.flags };
		const size_t page_offset = (addr.pte << pte_shift) + addr.page_off;

		if (flags)
		{
			*flags = compute_flags(pml4e, pdpte, large_pde);
		}

		return (large_pde.page_frame_number << pde_shift) + page_offset;
	}

	const auto pte = read_physical_memory<pte_64>(
		(pde.page_frame_number << page_shift) + addr.pte * sizeof(pte_64), &success);

	if (!success || !pte.present)
	{
		return { };
	}

	if (flags)
	{
		*flags = compute_flags(pml4e, pdpte, pde, pte);
	}

	return (pte.page_frame_number << pte_shift) + addr.page_off;
}

page_flags mem::virt_page_flags(const cr3 cr3, const virt_addr_t addr)
{
	page_flags flags = page_none;

	translate_virt_addr(cr3, addr, &flags);

	return flags;
}

bool mem::read_physical_memory(const phys_addr_t addr, void* const buffer, const size_t size)
{
	const PHYSICAL_ADDRESS phys_addr = { .QuadPart = static_cast<int64_t>(addr) };

	SIZE_T bytes_transferred = 0;

	const nt_status status = MmCopyMemory(buffer, MM_COPY_ADDRESS{ .PhysicalAddress = phys_addr }, size, MM_COPY_MEMORY_PHYSICAL, &bytes_transferred);

	return status && size == bytes_transferred;
}
