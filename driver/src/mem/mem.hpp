#pragma once
#include <array.hpp>
#include <cstdint>
#include <ntddk.h>
#include <ia32.hpp>
#include <optional.hpp>

union virt_addr_t
{
	virt_addr_t(const uint64_t value_)
		: value(value_) {
	}

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

namespace mem
{
	static constexpr size_t page_size = 0x1000;
	static constexpr size_t page_entries = 512;
	static constexpr size_t page_shift = 12;
	static constexpr size_t pte_shift = page_shift;
	static constexpr size_t pde_shift = 21;
	static constexpr size_t pdpte_shift = 30;

	using phys_addr_t = uintptr_t;

	template <class T>
	using paging_level_t = cstd::array<T, page_entries>;

	using pml4_t = paging_level_t<pml4e_64>;
	using pdpt_t = paging_level_t<pdpte_64>;
	using pd_t = paging_level_t<pde_64>;
	using pt_t = paging_level_t<pte_64>;

	cstd::optional<phys_addr_t> translate_virt_addr(cr3 cr3, virt_addr_t addr, page_flags* flags = nullptr);
	page_flags virt_page_flags(cr3 cr3, virt_addr_t addr);

	bool read_physical_memory(phys_addr_t addr, void* buffer, size_t size);

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
}
