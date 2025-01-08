#pragma once
#include "../context/context.h"

// when people reverse engineer our driver, they are going to grab a hypervisor
// and place breakpoints on nearly every export in ntoskrnl
// to make it harder for them, we are going to try minimize the amount of imports we use
// 
// hence we now can't use functions such as PsGetCurrentProcessId or PsLookupProcessByProcessId
// todo: use disassembler to figure out offsets by analyzing aforementioned functions

// starts at Windows 10 1507 up until Windows 11 24H2
namespace offsets
{
	bool load(context::s_context* context);

	namespace kthread
	{
		inline uint64_t apc_state = 0x98; // doesn't change at all (last checked: Windows 11 24H2)
		inline uint64_t process = 0x220; // doesn't change at all (last checked: Windows 11 24H2)
	}

	namespace ethread
	{
		inline uint64_t start_address = 0x600; // doesn't change until Windows 10 1607, Windows 10 2004, Windows 11 24H2 (last checked: Windows 11 24H2)
		inline uint64_t cid = 0x628; // doesn't change until Windows 10 1607, Windows 10 2004, Windows 11 24H2(last checked: Windows 11 24H2)
		inline uint64_t win32_start_address = 0x680; // doesn't change until Windows 10 1607, Windows 10 2004, Windows 11 24H2 (last checked: Windows 11 24H2)
	}

	namespace kapc_state
	{
		inline uint64_t process = 0x20; // doesn't change at all (last checked: Windows 11 24H2)
	}

	namespace kpcr
	{
		inline uint64_t tss_base = 0x8; // never changes
	}

	namespace eprocess
	{
		inline uint64_t directory_table_base = 0x28;
		inline uint64_t unique_process_id = 0x2E8; // doesn't change until Windows 10 1703, Windows 10 2004, Windows 11 24H2 (last checked: Windows 11 24H2)
		inline uint64_t active_process_links = 0; // always the same as (unique_process_id + 8) (last checked: Windows 11 24H2)
		inline uint64_t section_base_address = 0x3C0; // doesn't change until Windows 10 1903, Windows 10 2004, Windows 11 24H2 (last checked: Windows 11 24H2)
		inline uint64_t peb = 0x3F8; // doesn't change until Windows 10 2004, Windows 11 24H2 (last checked: Windows 11 24H2)
	}

	namespace ldr_data_table_entry
	{
		inline uint64_t in_memory_order_links = 0x10;
	}
}
