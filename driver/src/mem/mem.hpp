#pragma once
#include <array.hpp>
#include <cstdint>
#include <ntddk.h>
#include <ia32.hpp>
#include <optional.hpp>

#include "../krnl/nt_status.hpp"

namespace mem
{
	static constexpr size_t page_size = 0x1000;
	static constexpr size_t page_entries = 512;
	static constexpr size_t page_shift = 12;
	static constexpr size_t pte_shift = page_shift;
	static constexpr size_t pde_shift = 21;
	static constexpr size_t pdpte_shift = 30;

	union virt_addr_t
	{
		virt_addr_t(const uint64_t value_)
			:	value(value_) { }

		struct
		{
			uint64_t page_off : 12;
			uint64_t pte : 9;
			uint64_t pde : 9;
			uint64_t pdpte : 9;
			uint64_t pml4e : 9;
			uint64_t reserved : 16;
		};

		uint64_t value;
	};

	enum page_flags : uint8_t
	{
		page_none = 0,
		page_read = 1,
		page_write = 2,
		page_execute = 4,
		page_supervisor = 8
	};

	using phys_addr_t = uintptr_t;

	template <class T>
	using paging_level_t = cstd::array<T, page_entries>;

	using pml4_t = paging_level_t<pml4e_64>;
	using pdpt_t = paging_level_t<pdpte_64>;
	using pd_t = paging_level_t<pde_64>;
	using pt_t = paging_level_t<pte_64>;

	inline bool read_physical_memory(const phys_addr_t addr, void* const buffer, const size_t size)
	{
		const MM_COPY_ADDRESS copy_addr = { .PhysicalAddress.QuadPart = static_cast<int64_t>(addr) };

		SIZE_T bytes_transferred = 0;

		const nt_status status = MmCopyMemory(buffer, copy_addr, size, MM_COPY_MEMORY_PHYSICAL, &bytes_transferred);

		return status && size == bytes_transferred;
	}

	template <class T>
	T read_physical_memory(const phys_addr_t addr, bool* const succeeded = nullptr)
	{
		T value{};

		const bool status = read_physical_memory(addr, &value, sizeof(T));

		if (succeeded)
		{
			*succeeded = status;
		}

		return value;
	}

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

	inline cstd::optional<phys_addr_t> translate_virt_addr(const cr3 cr3, const virt_addr_t addr, page_flags* const flags = nullptr)
	{
		if (flags)
		{
			*flags = page_none;
		}

		bool success = false;

		const auto pml4 = read_physical_memory<pml4_t>(cr3.address_of_page_directory << page_shift, &success);
		const auto pml4e = pml4[addr.pml4e];

		if (!success || !pml4e.present)
		{
			return { };
		}

		const auto pdpt = read_physical_memory<pdpt_t>(pml4e.page_frame_number << page_shift, &success);
		const auto pdpte = pdpt[addr.pdpte];

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

		const auto pd = read_physical_memory<pd_t>(pml4e.page_frame_number << page_shift, &success);
		const auto pde = pd[addr.pde];

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

		const auto pt = read_physical_memory<pt_t>(pml4e.page_frame_number << page_shift, &success);
		const auto pte = pt[addr.pte];

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

	inline page_flags virt_page_flags(const cr3 cr3, const virt_addr_t addr)
	{
		page_flags flags = page_none;

		translate_virt_addr(cr3, addr, &flags);

		return flags;
	}
}
